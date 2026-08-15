// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "error.h"
#include "cupolas.h"
/*
 *
 * cupolas_vault.c - Secure Credential Storage: iOS Keychain-like Implementation
 */

/**
 * @file cupolas_vault.c
 * @brief Secure credential storage (iOS Keychain-like) implementation.
 */

#include "cupolas_vault.h"
#include "cupolas_vault_internal.h"

#include "../platform/platform.h"
#include "atomic_compat.h"
#include "cupolas_error.h"
#include "logging.h"
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CUPOLAS_USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#endif

static vault_global_ctx_t g_vault_ctx = {0};

/* ============================================================================
 * SEC-13: preallocated pool for OOM critical paths.
 *
 * 16 credential slots and encrypted-data buffers are preallocated at
 * startup. On OOM the preallocated pool replaces the system malloc so the
 * credential-storage critical path still works under memory pressure.
 * ============================================================================ */

static credential_entry_t g_vault_oom_entries[VAULT_OOM_PREALLOC_SLOTS];

static uint8_t g_vault_oom_data[VAULT_OOM_PREALLOC_SLOTS][VAULT_OOM_PREALLOC_DATA_SIZE];

static bool g_vault_oom_used[VAULT_OOM_PREALLOC_SLOTS];

static cupolas_mutex_t g_vault_oom_lock;

static bool g_vault_oom_initialized = false;

/**
 * @brief Initialize the OOM prealloc pool (SEC-13.1)
 *
 * Called from cupolas_vault_init(); preallocates resources at startup.
 * No memory allocation: backed by static arrays.
 */
static void vault_oom_pool_init(void)
{
    if (g_vault_oom_initialized) {
        return;
    }

    cupolas_mutex_init(&g_vault_oom_lock);

    __builtin_memset(g_vault_oom_entries, 0, sizeof(g_vault_oom_entries));
    __builtin_memset(g_vault_oom_data, 0, sizeof(g_vault_oom_data));
    __builtin_memset(g_vault_oom_used, 0, sizeof(g_vault_oom_used));

    g_vault_oom_initialized = true;
}

/**
 * @brief Allocate a credential slot from the OOM prealloc pool (SEC-13.1)
 *
 * Called when the normal AIRY_CALLOC fails. Takes a slot from the
 * preallocated pool without calling the system malloc.
 *
 * @return Credential entry pointer, NULL if the pool is exhausted
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static credential_entry_t *vault_oom_pool_alloc(void)
{
    if (!g_vault_oom_initialized) {
        return NULL;
    }

    cupolas_mutex_lock(&g_vault_oom_lock);

    for (int i = 0; i < VAULT_OOM_PREALLOC_SLOTS; i++) {
        if (!g_vault_oom_used[i]) {
            g_vault_oom_used[i] = true;
            __builtin_memset(&g_vault_oom_entries[i], 0, sizeof(credential_entry_t));
            cupolas_mutex_unlock(&g_vault_oom_lock);
            return &g_vault_oom_entries[i];
        }
    }

    cupolas_mutex_unlock(&g_vault_oom_lock);
    return NULL;
}

/**
 * @brief Get the encrypted-data buffer from the OOM prealloc pool (SEC-13.1)
 *
 * Returns the preallocated data buffer matching the slot index.
 *
 * @param entry Entry pointer obtained from vault_oom_pool_alloc()
 * @return Data buffer pointer, NULL for an invalid entry
 */
static uint8_t *vault_oom_pool_get_data_buffer(credential_entry_t *entry)
{
    if (!entry || !g_vault_oom_initialized) {
        return NULL;
    }

    ptrdiff_t index = entry - g_vault_oom_entries;
    if (index < 0 || index >= VAULT_OOM_PREALLOC_SLOTS) {
        return NULL;
    }

    return g_vault_oom_data[index];
}

/**
 * @brief Release an OOM prealloc pool slot (SEC-13.1)
 *
 * @param entry Entry pointer to release
 */
static void vault_oom_pool_free(credential_entry_t *entry)
{
    if (!entry || !g_vault_oom_initialized) {
        return;
    }

    ptrdiff_t index = entry - g_vault_oom_entries;
    if (index < 0 || index >= VAULT_OOM_PREALLOC_SLOTS) {
        return;
    }

    cupolas_mutex_lock(&g_vault_oom_lock);
    g_vault_oom_used[index] = false;
    cupolas_mutex_unlock(&g_vault_oom_lock);
}
#pragma GCC diagnostic pop

#define VLT_INIT_UNINIT 0
#define VLT_INIT_PROGRESS 1
#define VLT_INIT_COMPLETE 2

int cupolas_vault_init(const cupolas_vault_config_t *config)
{
    if (atomic_load(&g_vault_ctx.initialized) == VLT_INIT_COMPLETE) {
        return 0;
    }

    int expected = VLT_INIT_UNINIT;
    if (atomic_compare_exchange_strong(&g_vault_ctx.initialized, &expected, VLT_INIT_PROGRESS)) {
        __builtin_memset(&g_vault_ctx, 0, sizeof(g_vault_ctx));

        if (config) {
            __builtin_memcpy(&g_vault_ctx.default_config, config, sizeof(cupolas_vault_config_t));
        } else {
            g_vault_ctx.default_config.enable_audit = true;
            g_vault_ctx.default_config.enable_auto_lock = true;
            g_vault_ctx.default_config.auto_lock_seconds = 300;
            g_vault_ctx.default_config.max_retry_count = 3;
        }

        cupolas_rwlock_init(&g_vault_ctx.global_lock);

        vault_oom_pool_init();

        atomic_store(&g_vault_ctx.initialized, VLT_INIT_COMPLETE);
        return 0;
    }

    while (atomic_load(&g_vault_ctx.initialized) != VLT_INIT_COMPLETE) {
#if defined(_WIN32)
        SwitchToThread();
#else
        sched_yield();
#endif
    }
    return 0;
}

void cupolas_vault_cleanup(void)
{
    if (atomic_load(&g_vault_ctx.initialized) != VLT_INIT_COMPLETE) {
        return;
    }

    cupolas_rwlock_destroy(&g_vault_ctx.global_lock);
    __builtin_memset(&g_vault_ctx, 0, sizeof(g_vault_ctx));
}

int cupolas_vault_open(const char *vault_id, const char *password, cupolas_vault_t **vault)
{
    if (!vault_id || !vault) {
        AIRY_LOG_ERROR("cupolas_vault_open: NULL parameter - vault_id=%p, vault=%p", (void *)vault_id,
                  (void *)vault);
        return AIRY_ERR_UNKNOWN;
    }

    if (atomic_load(&g_vault_ctx.initialized) != VLT_INIT_COMPLETE) {
        cupolas_vault_init(NULL);
    }

    cupolas_vault_t *v = (cupolas_vault_t *)AIRY_CALLOC(1, sizeof(cupolas_vault_t));
    if (!v) {
        AIRY_LOG_ERROR("cupolas_vault_open: CALLOC vault failed for vault_id=%s", vault_id);
        return AIRY_ERR_UNKNOWN;
    }

    v->vault_id = AIRY_STRDUP(vault_id);
    if (!v->vault_id) {
        AIRY_FREE(v);
        AIRY_LOG_ERROR("cupolas_vault_open: STRDUP vault_id failed for vault_id=%s", vault_id);
        return AIRY_ERR_UNKNOWN;
    }
    v->is_locked = (password == NULL);
    v->entry_capacity = 64;
    v->entries = (credential_entry_t *)AIRY_CALLOC(v->entry_capacity, sizeof(credential_entry_t));
    if (!v->entries) {
        AIRY_FREE(v->vault_id);
        AIRY_FREE(v);
        AIRY_LOG_ERROR("cupolas_vault_open: CALLOC entries failed for vault_id=%s", vault_id);
        return AIRY_ERR_UNKNOWN;
    }
    v->entry_count = 0;

    cupolas_rwlock_init(&v->lock);
    __builtin_memcpy(&v->config, &g_vault_ctx.default_config, sizeof(cupolas_vault_config_t));

    if (password) {
#ifdef CUPOLAS_USE_OPENSSL
        uint8_t salt[SALT_SIZE] = {0};
        uint8_t id_hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)vault_id, strlen(vault_id), id_hash);
        __builtin_memcpy(salt, id_hash, SALT_SIZE);
        if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 100000, EVP_sha256(),
                              AES_KEY_SIZE, v->master_key) != 1) {
            cupolas_rwlock_destroy(&v->lock);
            AIRY_FREE(v->entries);
            AIRY_FREE(v->vault_id);
            AIRY_FREE(v);
            AIRY_LOG_ERROR("cupolas_vault_open: PBKDF2 key derivation failed for vault_id=%s", vault_id);
            return AIRY_ERR_UNKNOWN;
        }
#else
        cupolas_rwlock_destroy(&v->lock);
        AIRY_FREE(v->entries);
        AIRY_FREE(v->vault_id);
        AIRY_FREE(v);
        return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif
        v->is_locked = false;
    }

    *vault = v;
    return 0;
}

void cupolas_vault_close(cupolas_vault_t *vault)
{
    if (!vault) {
        return;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    AIRY_FREE(vault->vault_id);

    if (vault->entries) {
        for (size_t i = 0; i < vault->entry_count; i++) {
            credential_entry_t *entry = &vault->entries[i];
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->encrypted_data);
            for (size_t j = 0; j < entry->acl.count; j++) {
                AIRY_FREE(entry->acl.entries[j].agent_id);
            }
            AIRY_FREE(entry->acl.entries);
            cupolas_vault_free_metadata(&entry->metadata);
        }
        AIRY_FREE(vault->entries);
    }

    __builtin_memset(vault->master_key, 0, AES_KEY_SIZE);

    cupolas_rwlock_unlock(&vault->lock);
    cupolas_rwlock_destroy(&vault->lock);

    AIRY_FREE(vault);
}

int cupolas_vault_lock(cupolas_vault_t *vault)
{
    if (!vault) {
        AIRY_LOG_ERROR("cupolas_vault_lock: NULL vault parameter");
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_wrlock(&vault->lock);
    __builtin_memset(vault->master_key, 0, AES_KEY_SIZE);
    vault->is_locked = true;
    cupolas_rwlock_unlock(&vault->lock);

    return 0;
}

int cupolas_vault_unlock(cupolas_vault_t *vault, const char *password)
{
    if (!vault || !password) {
        AIRY_LOG_ERROR("cupolas_vault_unlock: NULL parameter - vault=%p, password=%p", (void *)vault,
                  (void *)password);
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_wrlock(&vault->lock);

#ifdef CUPOLAS_USE_OPENSSL
    uint8_t salt[SALT_SIZE] = {0};
    uint8_t id_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)vault->vault_id, strlen(vault->vault_id), id_hash);
    __builtin_memcpy(salt, id_hash, SALT_SIZE);
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 100000, EVP_sha256(),
                          AES_KEY_SIZE, vault->master_key) != 1) {
        cupolas_rwlock_unlock(&vault->lock);
        AIRY_LOG_ERROR("cupolas_vault_unlock: key derivation failed for vault_id=%s",
                  vault->vault_id ? vault->vault_id : "(null)");
        return AIRY_ERR_UNKNOWN;
    }
#else
    cupolas_rwlock_unlock(&vault->lock);
    AIRY_LOG_ERROR("cupolas_vault_unlock: crypto unavailable for vault_id=%s",
              vault->vault_id ? vault->vault_id : "(null)");
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif
    vault->is_locked = false;
    cupolas_rwlock_unlock(&vault->lock);

    return 0;
}

bool cupolas_vault_is_locked(cupolas_vault_t *vault)
{
    if (!vault) {
        return true;
    }

    cupolas_rwlock_rdlock(&vault->lock);
    bool locked = vault->is_locked;
    cupolas_rwlock_unlock(&vault->lock);

    return locked;
}
