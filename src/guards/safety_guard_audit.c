// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_audit.c
 * @brief V2 SafetyGuard API 实现 - 审核域
 *
 * 本文件实现审计记录的写入与查询。
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

int safety_guard_record_audit(safety_guard_context_t *ctx, const safety_event_t *event,
                              const safety_result_t *result, const char *guard_name)
{
    if (!ctx || !event)
        return AIRY_ERR_INVALID_PARAM;

    if (ctx->audit_count >= ctx->audit_capacity) {

        size_t new_cap = ctx->audit_capacity * 2;
        if (new_cap > SAFETY_MAX_AUDIT_ENTRIES)
            new_cap = SAFETY_MAX_AUDIT_ENTRIES;
        if (ctx->audit_count >= new_cap)
            return AIRY_ERR_FAIL;

        safety_audit_entry_t *new_entries =
            (safety_audit_entry_t *)AIRY_REALLOC(ctx->audit_entries,
                                                 new_cap * sizeof(safety_audit_entry_t));
        if (!new_entries)
            return AIRY_ERR_OUT_OF_MEMORY;
        ctx->audit_entries = new_entries;
        ctx->audit_capacity = new_cap;
    }

    safety_audit_entry_t *entry = &ctx->audit_entries[ctx->audit_count];
    __builtin_memset(entry, 0, sizeof(*entry));
    entry->event_id = ctx->audit_count;
    entry->event_type = event->type;
    snprintf(entry->subject, sizeof(entry->subject), "%s", event->subject);
    snprintf(entry->action, sizeof(entry->action), "%s", event->action);
    entry->decision = result ? result->decision : SAFETY_DECISION_ALLOW;
    if (result && result->reason[0]) {
        snprintf(entry->reason, sizeof(entry->reason), "%s", result->reason);
    }
    if (guard_name) {
        snprintf(entry->guard_name, sizeof(entry->guard_name), "%s", guard_name);
    }
    entry->timestamp = event->timestamp;

    ctx->audit_count++;
    return 0;
}

int safety_guard_query_audit(safety_guard_context_t *ctx, const char *subject,
                             uint64_t from_timestamp, uint64_t to_timestamp,
                             safety_audit_entry_t **entries, size_t *entry_count)
{
    if (!ctx) {
        if (entries)
            *entries = NULL;
        if (entry_count)
            *entry_count = 0;
        return AIRY_ERR_INVALID_PARAM;
    }

    size_t match_count = 0;
    for (size_t i = 0; i < ctx->audit_count; i++) {
        safety_audit_entry_t *e = &ctx->audit_entries[i];
        if (subject && subject[0] && __builtin_strcmp(e->subject, subject) != 0)
            continue;
        if (from_timestamp > 0 && e->timestamp < from_timestamp)
            continue;
        if (to_timestamp > 0 && e->timestamp > to_timestamp)
            continue;
        match_count++;
    }

    if (match_count == 0) {
        if (entries)
            *entries = NULL;
        if (entry_count)
            *entry_count = 0;
        return 0;
    }

    safety_audit_entry_t *result =
        (safety_audit_entry_t *)AIRY_CALLOC(match_count, sizeof(safety_audit_entry_t));
    if (!result)
        return AIRY_ERR_OUT_OF_MEMORY;

    size_t idx = 0;
    for (size_t i = 0; i < ctx->audit_count; i++) {
        safety_audit_entry_t *e = &ctx->audit_entries[i];
        if (subject && subject[0] && __builtin_strcmp(e->subject, subject) != 0)
            continue;
        if (from_timestamp > 0 && e->timestamp < from_timestamp)
            continue;
        if (to_timestamp > 0 && e->timestamp > to_timestamp)
            continue;
        __builtin_memcpy(&result[idx], e, sizeof(*e));
        idx++;
    }

    if (entries)
        *entries = result;
    if (entry_count)
        *entry_count = match_count;
    return 0;
}
