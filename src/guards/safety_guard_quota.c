// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_quota.c
 * @brief V2 SafetyGuard API 实现 - 配额控制域
 *
 * 本文件实现资源配额的设置、检查、消费与释放。
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

int safety_guard_set_quota(safety_guard_context_t *ctx, const char *resource_id, int64_t limit,
                           uint64_t reset_interval_ms)
{
    if (!ctx || !resource_id)
        return AIRY_ERR_INVALID_PARAM;

    for (size_t i = 0; i < ctx->quota_count; i++) {
        if (__builtin_strcmp(ctx->quotas[i].resource_id, resource_id) == 0) {
            ctx->quotas[i].limit = limit;
            ctx->quotas[i].reset_interval_ms = reset_interval_ms;
            return 0;
        }
    }

    if (ctx->quota_count >= ctx->quota_capacity)
        return AIRY_ERR_FAIL;
    safety_quota_t *q = &ctx->quotas[ctx->quota_count];
    snprintf(q->resource_id, sizeof(q->resource_id), "%s", resource_id);
    q->limit = limit;
    q->current_usage = 0;
    q->reserved = 0;
    q->reset_interval_ms = reset_interval_ms;
    q->last_reset = 0;
    ctx->quota_count++;
    return 0;
}

int safety_guard_check_quota(safety_guard_context_t *ctx, const char *resource_id,
                             int64_t requested, bool *allowed)
{
    if (!ctx || !resource_id || !allowed)
        return AIRY_ERR_INVALID_PARAM;

    for (size_t i = 0; i < ctx->quota_count; i++) {
        if (__builtin_strcmp(ctx->quotas[i].resource_id, resource_id) == 0) {
            *allowed = (ctx->quotas[i].current_usage + requested) <= ctx->quotas[i].limit;
            return 0;
        }
    }
    *allowed = true;
    return 0;
}

int safety_guard_consume_quota(safety_guard_context_t *ctx, const char *resource_id, int64_t amount)
{
    if (!ctx || !resource_id)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->quota_count; i++) {
        if (__builtin_strcmp(ctx->quotas[i].resource_id, resource_id) == 0) {
            ctx->quotas[i].current_usage += amount;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

int safety_guard_release_quota(safety_guard_context_t *ctx, const char *resource_id, int64_t amount)
{
    if (!ctx || !resource_id)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->quota_count; i++) {
        if (__builtin_strcmp(ctx->quotas[i].resource_id, resource_id) == 0) {
            ctx->quotas[i].current_usage -= amount;
            if (ctx->quotas[i].current_usage < 0)
                ctx->quotas[i].current_usage = 0;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}
