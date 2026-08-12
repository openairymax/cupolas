// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_metadata.c
 * @brief 元数据域：凭证元数据查询、释放与列表管理
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

/* ============================================================================
 * 元数据操作
 * ============================================================================ */

int cupolas_vault_get_metadata(cupolas_vault_t *vault, const char *cred_id,
                               cupolas_vault_metadata_t *metadata)
{
    if (!vault || !cred_id || !metadata) {
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_rdlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_INVALID_PARAM;
    }

    metadata->cred_id = AIRY_STRDUP(entry->metadata.cred_id);
    metadata->type = entry->metadata.type;
    metadata->created_at = entry->metadata.created_at;
    metadata->updated_at = entry->metadata.updated_at;
    metadata->expires_at = entry->metadata.expires_at;
    metadata->is_accessible = !vault->is_locked;

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

void cupolas_vault_free_metadata(cupolas_vault_metadata_t *metadata)
{
    if (!metadata) {
        return;
    }

    AIRY_FREE(metadata->cred_id);
    AIRY_FREE(metadata->description);
    AIRY_FREE(metadata->service);
    AIRY_FREE(metadata->account);
    __builtin_memset(metadata, 0, sizeof(cupolas_vault_metadata_t));
}

int cupolas_vault_list(cupolas_vault_t *vault, cupolas_vault_cred_type_t type,
                       cupolas_vault_metadata_t **metadata_array, size_t *count)
{
    if (!vault || !metadata_array || !count) {
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_rdlock(&vault->lock);

    size_t match_count = 0;
    for (size_t i = 0; i < vault->entry_count; i++) {
        if (type == 0 || vault->entries[i].type == type) {
            match_count++;
        }
    }

    if (match_count == 0) {
        *metadata_array = NULL;
        *count = 0;
        cupolas_rwlock_unlock(&vault->lock);
        return 0;
    }

    cupolas_vault_metadata_t *arr = AIRY_CALLOC(match_count, sizeof(cupolas_vault_metadata_t));
    if (!arr) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_INVALID_PARAM;
    }

    size_t idx = 0;
    for (size_t i = 0; i < vault->entry_count; i++) {
        if (type == 0 || vault->entries[i].type == type) {
            arr[idx].cred_id = AIRY_STRDUP(vault->entries[i].cred_id);
            arr[idx].type = vault->entries[i].type;
            arr[idx].created_at = vault->entries[i].metadata.created_at;
            arr[idx].updated_at = vault->entries[i].metadata.updated_at;
            idx++;
        }
    }

    *metadata_array = arr;
    *count = match_count;

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

void cupolas_vault_free_list(cupolas_vault_metadata_t *metadata_array, size_t count)
{
    if (!metadata_array) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        cupolas_vault_free_metadata(&metadata_array[i]);
    }
    AIRY_FREE(metadata_array);
}
