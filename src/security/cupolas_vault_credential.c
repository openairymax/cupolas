// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_credential.c
 * @brief Credential store domain: credential CRUD and AES-256-GCM
 *        encrypted storage.
 */

#include "error.h"
#include "cupolas.h"
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

credential_entry_t *find_entry(cupolas_vault_t *vault, const char *cred_id)
{
    for (size_t i = 0; i < vault->entry_count; i++) {
        if (strcmp(vault->entries[i].cred_id, cred_id) == 0) {
            return &vault->entries[i];
        }
    }
    return NULL;
}

int cupolas_vault_store(cupolas_vault_t *vault, const char *cred_id, cupolas_vault_cred_type_t type,
                        const uint8_t *data, size_t data_len, const cupolas_vault_acl_t *acl)
{
    if (!vault || !cred_id || !data || data_len == 0) {
        AIRY_LOG_ERROR("cupolas_vault_store: NULL/invalid parameter - vault=%p, cred_id=%p, data=%p, "
                  "data_len=%zu",
                  (void *)vault, (void *)cred_id, (void *)data, data_len);
        return AIRY_ERR_UNKNOWN;
    }

    if (vault->is_locked) {
        return cupolas_ERR_INVALID_PARAM;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    if (vault->entry_count >= vault->entry_capacity) {
        size_t new_capacity = vault->entry_capacity * 2;
        credential_entry_t *new_entries =
            AIRY_REALLOC(vault->entries, new_capacity * sizeof(credential_entry_t));
        if (!new_entries) {
            cupolas_rwlock_unlock(&vault->lock);
            return cupolas_ERR_NULL_POINTER;
        }
        vault->entries = new_entries;
        vault->entry_capacity = new_capacity;
    }

    credential_entry_t *entry = find_entry(vault, cred_id);
    int existed = (entry != NULL);
    if (entry) {
        AIRY_FREE(entry->encrypted_data);
        entry->encrypted_data = NULL;
        AIRY_FREE(entry->metadata.cred_id);
        entry->metadata.cred_id = NULL;
    } else {
        entry = &vault->entries[vault->entry_count];
        __builtin_memset(entry, 0, sizeof(credential_entry_t));
        entry->cred_id = AIRY_STRDUP(cred_id);
    }

    entry->type = type;
    entry->metadata.cred_id = AIRY_STRDUP(cred_id);
    entry->metadata.type = type;
    entry->metadata.created_at = (uint64_t)time(NULL);
    entry->metadata.updated_at = entry->metadata.created_at;

#ifdef CUPOLAS_USE_OPENSSL
    if (RAND_bytes(entry->iv, AES_IV_SIZE) != 1 || RAND_bytes(entry->salt, SALT_SIZE) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_store: RAND_bytes failed for cred_id=%s", cred_id);
        if (!existed) {
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->metadata.cred_id);
            __builtin_memset(entry, 0, sizeof(credential_entry_t));
        }
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        AIRY_LOG_ERROR("cupolas_vault_store: EVP_CIPHER_CTX_new failed for cred_id=%s", cred_id);
        if (!existed) {
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->metadata.cred_id);
            __builtin_memset(entry, 0, sizeof(credential_entry_t));
        } else {
            entry->encrypted_data = NULL;
        }
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    int len = 0;
    size_t ciphertext_len = data_len + AES_BLOCK_SIZE;
    entry->encrypted_data = (uint8_t *)AIRY_MALLOC(ciphertext_len);
    if (!entry->encrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        if (!existed) {
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->metadata.cred_id);
            __builtin_memset(entry, 0, sizeof(credential_entry_t));
        } else {
            entry->encrypted_data = NULL;
        }
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, vault->master_key, entry->iv) != 1 ||
        EVP_EncryptUpdate(ctx, entry->encrypted_data, &len, data, data_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, entry->encrypted_data + len, &len) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_store: AES-GCM encryption failed for cred_id=%s, data_len=%zu",
                  cred_id, data_len);
        AIRY_FREE(entry->encrypted_data);
        entry->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        if (!existed) {
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->metadata.cred_id);
            __builtin_memset(entry, 0, sizeof(credential_entry_t));
        } else {
            entry->encrypted_data = NULL;
        }
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, entry->tag) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_store: GCM tag extraction failed for cred_id=%s", cred_id);
        AIRY_FREE(entry->encrypted_data);
        entry->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        if (!existed) {
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->metadata.cred_id);
            __builtin_memset(entry, 0, sizeof(credential_entry_t));
        } else {
            entry->encrypted_data = NULL;
        }
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    entry->encrypted_len = data_len;
    EVP_CIPHER_CTX_free(ctx);
#else
    AIRY_FREE(entry->metadata.cred_id);
    entry->metadata.cred_id = NULL;
    if (!existed) {
        AIRY_FREE(entry->cred_id);
        entry->cred_id = NULL;
    } else {
        entry->encrypted_data = NULL;
    }
    cupolas_rwlock_unlock(&vault->lock);
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif

    if (acl) {
        entry->acl.count = acl->count;
        entry->acl.entries = (cupolas_vault_acl_entry_t *)AIRY_MALLOC(
            acl->count * sizeof(cupolas_vault_acl_entry_t));
        if (!entry->acl.entries) {
            AIRY_FREE(entry->encrypted_data);
            entry->encrypted_data = NULL;
            entry->encrypted_len = 0;
            AIRY_FREE(entry->metadata.cred_id);
            entry->metadata.cred_id = NULL;
            if (!existed) {
                AIRY_FREE(entry->cred_id);
                entry->cred_id = NULL;
            } else {
                entry->encrypted_data = NULL;
            }
            cupolas_rwlock_unlock(&vault->lock);
            return cupolas_ERR_OUT_OF_MEMORY;
        }
        for (size_t i = 0; i < acl->count; i++) {
            entry->acl.entries[i].agent_id = AIRY_STRDUP(acl->entries[i].agent_id);
            if (!entry->acl.entries[i].agent_id) {
                for (size_t j = 0; j < i; j++) {
                    AIRY_FREE(entry->acl.entries[j].agent_id);
                    entry->acl.entries[j].agent_id = NULL;
                }
                AIRY_FREE(entry->acl.entries);
                entry->acl.entries = NULL;
                entry->acl.count = 0;
                AIRY_FREE(entry->encrypted_data);
                entry->encrypted_data = NULL;
                entry->encrypted_len = 0;
                AIRY_FREE(entry->metadata.cred_id);
                entry->metadata.cred_id = NULL;
                if (!existed) {
                    AIRY_FREE(entry->cred_id);
                    entry->cred_id = NULL;
                }
                cupolas_rwlock_unlock(&vault->lock);
                return cupolas_ERR_OUT_OF_MEMORY;
            }
            entry->acl.entries[i].operations = acl->entries[i].operations;
            entry->acl.entries[i].expires_at = acl->entries[i].expires_at;
        }
    }

    if (!existed) {
        vault->entry_count++;
    }

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

int cupolas_vault_retrieve(cupolas_vault_t *vault, const char *cred_id, const char *agent_id,
                           uint8_t *data_out, size_t *data_len)
{
    if (!vault || !cred_id || !data_out || !data_len) {
        AIRY_LOG_ERROR("cupolas_vault_retrieve: NULL parameter - vault=%p, cred_id=%p, data_out=%p, "
                  "data_len=%p",
                  (void *)vault, (void *)cred_id, (void *)data_out, (void *)data_len);
        return AIRY_ERR_UNKNOWN;
    }

    if (vault->is_locked) {
        return cupolas_ERR_INVALID_PARAM;
    }

    cupolas_rwlock_rdlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NULL_POINTER;
    }

    if (!cupolas_vault_check_access(vault, cred_id, agent_id, CUPOLAS_VAULT_OP_READ)) {
        AIRY_LOG_WARN(
            "cupolas_vault_retrieve: access denied for agent_id=%s, cred_id=%s, operation=READ",
            agent_id ? agent_id : "(null)", cred_id);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    if (*data_len < entry->encrypted_len) {
        *data_len = entry->encrypted_len;
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_BUFFER_TOO_SMALL;
    }

#ifdef CUPOLAS_USE_OPENSSL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NOT_FOUND;
    }

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, vault->master_key, entry->iv) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_retrieve: DecryptInit failed for cred_id=%s", cred_id);
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NOT_FOUND;
    }
    if (EVP_DecryptUpdate(ctx, data_out, &len, entry->encrypted_data, entry->encrypted_len) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_retrieve: DecryptUpdate failed for cred_id=%s, encrypted_len=%zu",
                  cred_id, entry->encrypted_len);
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NOT_FOUND;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, entry->tag) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_retrieve: GCM tag set failed for cred_id=%s", cred_id);
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NOT_FOUND;
    }
    if (EVP_DecryptFinal_ex(ctx, data_out + len, &len) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_retrieve: credential decryption failed (tampered/corrupted) for "
                  "cred_id=%s",
                  cred_id);
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NOT_FOUND;
    }

    *data_len = entry->encrypted_len;
    EVP_CIPHER_CTX_free(ctx);
#else
    (void)data_out;
    cupolas_rwlock_unlock(&vault->lock);
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

int cupolas_vault_delete(cupolas_vault_t *vault, const char *cred_id, const char *agent_id)
{
    if (!vault || !cred_id) {
        AIRY_LOG_ERROR("cupolas_vault_delete: NULL parameter - vault=%p, cred_id=%p", (void *)vault,
                  (void *)cred_id);
        return AIRY_ERR_UNKNOWN;
    }

    if (vault->is_locked) {
        return cupolas_ERR_INVALID_PARAM;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    for (size_t i = 0; i < vault->entry_count; i++) {
        if (strcmp(vault->entries[i].cred_id, cred_id) == 0) {
            credential_entry_t *entry = &vault->entries[i];
            AIRY_FREE(entry->cred_id);
            AIRY_FREE(entry->encrypted_data);
            for (size_t j = 0; j < entry->acl.count; j++) {
                AIRY_FREE(entry->acl.entries[j].agent_id);
            }
            AIRY_FREE(entry->acl.entries);

            __builtin_memmove(&vault->entries[i], &vault->entries[i + 1],
                              (vault->entry_count - i - 1) * sizeof(credential_entry_t));
            vault->entry_count--;

            cupolas_rwlock_unlock(&vault->lock);
            return 0;
        }
    }

    cupolas_rwlock_unlock(&vault->lock);
    return cupolas_ERR_NULL_POINTER;
}

bool cupolas_vault_exists(cupolas_vault_t *vault, const char *cred_id)
{
    if (!vault || !cred_id) {
        return false;
    }

    cupolas_rwlock_rdlock(&vault->lock);
    credential_entry_t *entry = find_entry(vault, cred_id);
    cupolas_rwlock_unlock(&vault->lock);

    return entry != NULL;
}

int cupolas_vault_update(cupolas_vault_t *vault, const char *cred_id, const uint8_t *data,
                         size_t data_len, const char *agent_id)
{
    if (!vault || !cred_id || !data) {
        AIRY_LOG_ERROR("cupolas_vault_update: NULL parameter - vault=%p, cred_id=%p, data=%p",
                  (void *)vault, (void *)cred_id, (void *)data);
        return AIRY_ERR_UNKNOWN;
    }

    if (!cupolas_vault_check_access(vault, cred_id, agent_id, CUPOLAS_VAULT_OP_WRITE)) {
        AIRY_LOG_WARN("cupolas_vault_update: access denied for agent_id=%s, cred_id=%s, operation=WRITE",
                 agent_id ? agent_id : "(null)", cred_id);
        return cupolas_ERR_INVALID_PARAM;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NULL_POINTER;
    }

    AIRY_FREE(entry->encrypted_data);
    entry->encrypted_data = NULL;
    entry->encrypted_len = 0;

#ifdef CUPOLAS_USE_OPENSSL
    if (RAND_bytes(entry->iv, AES_IV_SIZE) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_update: RAND_bytes failed for cred_id=%s", cred_id);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        AIRY_LOG_ERROR("cupolas_vault_update: EVP_CIPHER_CTX_new failed for cred_id=%s", cred_id);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    int len = 0;
    entry->encrypted_data = (uint8_t *)AIRY_MALLOC(data_len + AES_BLOCK_SIZE);
    if (!entry->encrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, vault->master_key, entry->iv) != 1 ||
        EVP_EncryptUpdate(ctx, entry->encrypted_data, &len, data, data_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, entry->encrypted_data + len, &len) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_update: AES-GCM encryption failed for cred_id=%s, data_len=%zu",
                  cred_id, data_len);
        AIRY_FREE(entry->encrypted_data);
        entry->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, entry->tag) != 1) {
        AIRY_LOG_ERROR("cupolas_vault_update: GCM tag extraction failed for cred_id=%s", cred_id);
        AIRY_FREE(entry->encrypted_data);
        entry->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    entry->encrypted_len = data_len;
    EVP_CIPHER_CTX_free(ctx);
#else
    cupolas_rwlock_unlock(&vault->lock);
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif

    entry->metadata.updated_at = (uint64_t)time(NULL);

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}
