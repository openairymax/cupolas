// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_access.c
 * @brief Access-control domain: ACL-based credential authorization, revoke,
 *        and validation.
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

bool cupolas_vault_check_access(cupolas_vault_t *vault, const char *cred_id, const char *agent_id,
                                cupolas_vault_operation_t operation)
{
    if (!vault || !cred_id || !agent_id) {
        AIRY_LOG_ERROR("cupolas_vault_check_access: NULL parameter - vault=%p, cred_id=%p, agent_id=%p",
                  (void *)vault, (void *)cred_id, (void *)agent_id);
        return false;
    }

    cupolas_rwlock_rdlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return false;
    }

    /* Deny by default (fail-closed): a credential without ACLs is not open
     * to any agent. The creator/user must explicitly grant_access to get
     * the corresponding operation permissions. */
    if (entry->acl.count == 0) {
        cupolas_rwlock_unlock(&vault->lock);
        AIRY_LOG_WARN("cupolas_vault_check_access: no ACL entries for cred_id=%s, access denied by "
                 "default (agent_id=%s)",
                 cred_id, agent_id);
        return false;
    }

    for (size_t i = 0; i < entry->acl.count; i++) {
        cupolas_vault_acl_entry_t *acl = &entry->acl.entries[i];
        if (strcmp(acl->agent_id, agent_id) == 0) {
            if (acl->expires_at > 0 && (uint64_t)time(NULL) > acl->expires_at) {
                AIRY_LOG_WARN("cupolas_vault_check_access: expired credential detected for agent_id=%s, "
                         "cred_id=%s, expires_at=%llu",
                         agent_id, cred_id, (unsigned long long)acl->expires_at);
                cupolas_rwlock_unlock(&vault->lock);
                return false;
            }

            if ((acl->operations & (uint32_t)operation) != 0) {
                cupolas_rwlock_unlock(&vault->lock);
                return true;
            }
        }
    }

    cupolas_rwlock_unlock(&vault->lock);
    AIRY_LOG_WARN("cupolas_vault_check_access: access denied for agent_id=%s, cred_id=%s, operation=%d",
             agent_id, cred_id, (int)operation);
    return false;
}

int cupolas_vault_grant_access(cupolas_vault_t *vault, const char *cred_id, const char *agent_id,
                               uint32_t operations, uint64_t expires_at)
{
    if (!vault || !cred_id || !agent_id) {
        AIRY_LOG_ERROR("cupolas_vault_grant_access: NULL parameter - vault=%p, cred_id=%p, agent_id=%p",
                  (void *)vault, (void *)cred_id, (void *)agent_id);
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < entry->acl.count; i++) {
        if (strcmp(entry->acl.entries[i].agent_id, agent_id) == 0) {
            entry->acl.entries[i].operations = operations;
            entry->acl.entries[i].expires_at = expires_at;
            cupolas_rwlock_unlock(&vault->lock);
            return 0;
        }
    }

    size_t new_count = entry->acl.count + 1;
    cupolas_vault_acl_entry_t *new_entries =
        AIRY_REALLOC(entry->acl.entries, new_count * sizeof(cupolas_vault_acl_entry_t));
    if (!new_entries) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_NULL_POINTER;
    }

    entry->acl.entries = new_entries;
    entry->acl.entries[entry->acl.count].agent_id = AIRY_STRDUP(agent_id);
    entry->acl.entries[entry->acl.count].operations = operations;
    entry->acl.entries[entry->acl.count].expires_at = expires_at;
    entry->acl.entries[entry->acl.count].access_count = 0;
    entry->acl.entries[entry->acl.count].max_access_count = 0;
    entry->acl.count = new_count;

    cupolas_rwlock_unlock(&vault->lock);
    return 0;
}

int cupolas_vault_revoke_access(cupolas_vault_t *vault, const char *cred_id, const char *agent_id)
{
    if (!vault || !cred_id || !agent_id) {
        AIRY_LOG_ERROR("cupolas_vault_revoke_access: NULL parameter - vault=%p, cred_id=%p, agent_id=%p",
                  (void *)vault, (void *)cred_id, (void *)agent_id);
        return AIRY_ERR_UNKNOWN;
    }

    cupolas_rwlock_wrlock(&vault->lock);

    credential_entry_t *entry = find_entry(vault, cred_id);
    if (!entry) {
        cupolas_rwlock_unlock(&vault->lock);
        return cupolas_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < entry->acl.count; i++) {
        if (strcmp(entry->acl.entries[i].agent_id, agent_id) == 0) {
            AIRY_FREE(entry->acl.entries[i].agent_id);
            __builtin_memmove(&entry->acl.entries[i], &entry->acl.entries[i + 1],
                              (entry->acl.count - i - 1) * sizeof(cupolas_vault_acl_entry_t));
            entry->acl.count--;
            cupolas_rwlock_unlock(&vault->lock);
            return 0;
        }
    }

    cupolas_rwlock_unlock(&vault->lock);
    return cupolas_ERR_NULL_POINTER;
}
