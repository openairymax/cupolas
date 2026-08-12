// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_rotation.c
 * @brief Credential rotation domain: strategy-based credential selection
 *        and ACL query/release.
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

static uint64_t vault_group_usage(const credential_entry_t *entry)
{
    uint64_t uses = 0;
    for (size_t k = 0; k < entry->acl.count; k++) {
        uses += entry->acl.entries[k].access_count;
    }
    return uses;
}

static uint64_t vault_group_limit(const credential_entry_t *entry)
{
    uint64_t limit = 0;
    for (size_t k = 0; k < entry->acl.count; k++) {
        limit += entry->acl.entries[k].max_access_count;
    }
    return limit;
}

int cupolas_vault_rotate_credential(cupolas_vault_t *vault, const char *cred_group,
                                    cupolas_vault_rotation_strategy_t strategy, char *selected_id,
                                    size_t id_buf_size)
{
    static const char *strategy_names[] = {"UNKNOWN", "ROUND_ROBIN", "LEAST_USED", "RATE_LIMITED",
                                           "PRIORITY"};
    const char *strategy_name = (strategy >= CUPOLAS_VAULT_ROTATE_ROUND_ROBIN &&
                                 strategy <= CUPOLAS_VAULT_ROTATE_PRIORITY) ?
                                    strategy_names[strategy] :
                                    "INVALID";

    if (!vault || !cred_group || !selected_id || id_buf_size == 0) {
        LOG_ERROR("cupolas_vault_rotate: invalid parameter - vault=%p, "
                  "cred_group=%s, selected_id=%p, id_buf_size=%zu",
                  (void *)vault, cred_group ? cred_group : "(null)", (void *)selected_id,
                  id_buf_size);
        return cupolas_ERR_INVALID_PARAM;
    }
    LOG_DEBUG("cupolas_vault_rotate: begin - group=%s strategy=%s(%d) id_buf_size=%zu", cred_group,
              strategy_name, (int)strategy, id_buf_size);

    cupolas_rwlock_rdlock(&vault->lock);

    if (vault->is_locked) {
        cupolas_rwlock_unlock(&vault->lock);
        LOG_WARN("cupolas_vault_rotate: vault locked, group=%s strategy=%s "
                 "— unlock first",
                 cred_group, strategy_name);
        return cupolas_ERR_PERMISSION_DENIED;
    }

    /* Credential-group semantics: cred_group is a credential-id prefix, and
     * credentials in a group share that prefix (e.g. "svc:pay:key-1" /
     * "svc:pay:key-2" both belong to group "svc:pay"). Rotation strategies
     * score the existing fields and uniformly pick the argmin:
     *  - ROUND_ROBIN : oldest updated_at (longest since rotation)
     *  - LEAST_USED  : smallest sum of ACL access_count in the group
     *  - RATE_LIMITED: lowest access_count/max_access_count usage
     *  - PRIORITY    : newest updated_at (most recently updated first) */
    size_t best_idx = 0;
    uint64_t best_score = 0;
    bool found = false;
    size_t group_len = strlen(cred_group);
    size_t candidate_count = 0;

    for (size_t i = 0; i < vault->entry_count; i++) {
        const credential_entry_t *entry = &vault->entries[i];
        if (!entry->cred_id || strncmp(entry->cred_id, cred_group, group_len) != 0) {
            continue;
        }

        uint64_t score = 0;
        switch (strategy) {
        case CUPOLAS_VAULT_ROTATE_ROUND_ROBIN:
            score = entry->metadata.updated_at;
            break;
        case CUPOLAS_VAULT_ROTATE_LEAST_USED:
            score = vault_group_usage(entry);
            break;
        case CUPOLAS_VAULT_ROTATE_RATE_LIMITED: {
            uint64_t uses = vault_group_usage(entry);
            uint64_t limit = vault_group_limit(entry);

            score = (limit > 0) ? (uses * 1000ULL) / limit : uses;
            break;
        }
        case CUPOLAS_VAULT_ROTATE_PRIORITY:
            score = UINT64_MAX - entry->metadata.updated_at;
            break;
        default:
            cupolas_rwlock_unlock(&vault->lock);
            LOG_ERROR("cupolas_vault_rotate: invalid strategy=%d for group=%s", (int)strategy,
                      cred_group);
            return cupolas_ERR_INVALID_PARAM;
        }

        candidate_count++;
        LOG_DEBUG("cupolas_vault_rotate: candidate[%zu] cred_id=%s score=%llu", candidate_count,
                  entry->cred_id, (unsigned long long)score);
        if (!found || score < best_score) {
            best_idx = i;
            best_score = score;
            found = true;
        }
    }

    cupolas_rwlock_unlock(&vault->lock);

    if (!found) {
        LOG_WARN("cupolas_vault_rotate: no credential matches group prefix "
                 "'%s' (entries=%zu, strategy=%s) — check cred_id prefix",
                 cred_group, vault->entry_count, strategy_name);
        return cupolas_ERR_NOT_FOUND;
    }

    const char *selected = vault->entries[best_idx].cred_id;
    if (strlen(selected) >= id_buf_size) {
        LOG_ERROR("cupolas_vault_rotate: selected_id too long (len=%zu, buf=%zu) "
                  "for cred_id=%s group=%s",
                  strlen(selected), id_buf_size, selected, cred_group);
        return cupolas_ERR_OVERFLOW;
    }
    snprintf(selected_id, id_buf_size, "%s", selected);
    LOG_INFO("cupolas_vault_rotate: selected=%s group=%s strategy=%s "
             "candidates=%zu score=%llu",
             selected, cred_group, strategy_name, candidate_count, (unsigned long long)best_score);
    return cupolas_ERR_OK;
}

int cupolas_vault_get_acl(cupolas_vault_t *vault, const char *cred_id, cupolas_vault_acl_t *acl)
{
    if (!vault || !cred_id || !acl) {
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_rdlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_INVALID_PARAM;
    }

    acl->count = entry->acl.count;
    acl->entries = AIRY_CALLOC(entry->acl.count, sizeof(cupolas_vault_acl_entry_t));
    if (!acl->entries && entry->acl.count > 0) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_OUT_OF_MEMORY;
    }
    for (size_t i = 0; i < entry->acl.count; i++) {
        acl->entries[i].agent_id = AIRY_STRDUP(entry->acl.entries[i].agent_id);
        acl->entries[i].operations = entry->acl.entries[i].operations;
        acl->entries[i].expires_at = entry->acl.entries[i].expires_at;
    }

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

void cupolas_vault_free_acl(cupolas_vault_acl_t *acl)
{
    if (!acl || !acl->entries) {
        return;
    }

    for (size_t i = 0; i < acl->count; i++) {
        AIRY_FREE(acl->entries[i].agent_id);
    }
    AIRY_FREE(acl->entries);
    acl->entries = NULL;
    acl->count = 0;
}
