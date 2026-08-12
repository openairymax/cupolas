// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_internal.h
 * @brief Vault internal shared definitions: constants, internal structures,
 *        and cross-file helper declarations.
 */

#ifndef CUPOLAS_VAULT_INTERNAL_H
#define CUPOLAS_VAULT_INTERNAL_H

#include "cupolas_vault.h"

#include "../platform/platform.h"
#include "atomic_compat.h"

#define VAULT_MAGIC 0x564C5453 /* "VLTS" */
#define VAULT_VERSION 1
#define MAX_CREDENTIALS 1024
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_GCM_TAG_SIZE 16
#define SALT_SIZE 32
#define MAX_ACL_ENTRIES_PER_CREDENTIAL 64

#define VAULT_OOM_PREALLOC_SLOTS 16
#define VAULT_OOM_PREALLOC_DATA_SIZE 4096

typedef struct {
    char *cred_id;
    cupolas_vault_cred_type_t type;
    uint8_t *encrypted_data;
    size_t encrypted_len;
    uint8_t iv[AES_IV_SIZE];
    uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t salt[SALT_SIZE];
    cupolas_vault_acl_t acl;
    cupolas_vault_metadata_t metadata;
} credential_entry_t;

struct cupolas_vault {
    char *vault_id;
    bool is_locked;
    uint8_t master_key[AES_KEY_SIZE];
    credential_entry_t *entries;
    size_t entry_count;
    size_t entry_capacity;
    cupolas_rwlock_t lock;
    cupolas_vault_config_t config;
};

typedef struct {
    atomic_int initialized;
    cupolas_vault_config_t default_config;
    cupolas_rwlock_t global_lock;
} vault_global_ctx_t;

credential_entry_t *find_entry(cupolas_vault_t *vault, const char *cred_id);

#endif /* CUPOLAS_VAULT_INTERNAL_H */
