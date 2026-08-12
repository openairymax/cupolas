// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard.c
 * @brief V2 SafetyGuard API 实现 - 生命周期与守卫注册域
 *
 * 本文件保留 SafetyGuard 的入口与核心状态机：上下文创建/销毁、
 * 守卫注册/注销/启用/禁用与数量查询。
 *
 * P1.4: C-L05 Cupolas SafetyGuard → tool_d 工具审批
 * 实现 6 种守卫类型与 tool_d 的映射：
 *   - SAFETY_GUARD_PERMISSION    → RBAC 权限检查
 *   - SAFETY_GUARD_RATE_LIMIT    → 工具调用频率限制
 *   - SAFETY_GUARD_CONTENT_FILTER → 输入内容过滤
 *   - SAFETY_GUARD_INPUT         → 参数净化
 *   - SAFETY_GUARD_RESOURCE      → 资源配额检查
 *   - SAFETY_GUARD_AUDIT         → 审计日志记录
 *
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

safety_guard_context_t *safety_guard_create(void)
{
    safety_guard_context_t *ctx = (safety_guard_context_t *)AIRY_CALLOC(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->guard_capacity = SAFETY_MAX_GUARDS;
    ctx->guards = (guard_entry_t *)AIRY_CALLOC(ctx->guard_capacity, sizeof(guard_entry_t));
    if (!ctx->guards) {
        AIRY_FREE(ctx);
        return NULL;
    }

    ctx->audit_capacity = 256;
    ctx->audit_entries =
        (safety_audit_entry_t *)AIRY_CALLOC(ctx->audit_capacity, sizeof(safety_audit_entry_t));
    if (!ctx->audit_entries) {
        AIRY_FREE(ctx->guards);
        AIRY_FREE(ctx);
        return NULL;
    }

    ctx->policy_capacity = 16;
    ctx->policies = (safety_policy_t *)AIRY_CALLOC(ctx->policy_capacity, sizeof(safety_policy_t));
    if (!ctx->policies) {
        AIRY_FREE(ctx->audit_entries);
        AIRY_FREE(ctx->guards);
        AIRY_FREE(ctx);
        return NULL;
    }

    ctx->quota_capacity = 32;
    ctx->quotas = (safety_quota_t *)AIRY_CALLOC(ctx->quota_capacity, sizeof(safety_quota_t));
    if (!ctx->quotas) {
        AIRY_FREE(ctx->policies);
        AIRY_FREE(ctx->audit_entries);
        AIRY_FREE(ctx->guards);
        AIRY_FREE(ctx);
        return NULL;
    }

    ctx->initialized = true;
    ctx->emergency_stopped = false;
    return ctx;
}

void safety_guard_destroy(safety_guard_context_t *ctx)
{
    if (!ctx)
        return;
    AIRY_FREE(ctx->quotas);

    for (size_t i = 0; i < ctx->policy_count; i++) {
        AIRY_FREE(ctx->policies[i].rules_json);
    }
    AIRY_FREE(ctx->policies);
    AIRY_FREE(ctx->audit_entries);
    AIRY_FREE(ctx->guards);
    AIRY_FREE(ctx);
}

int safety_guard_register_guard(safety_guard_context_t *ctx,
                                const safety_guard_descriptor_t *descriptor,
                                safety_guard_check_fn check_fn, void *user_data)
{
    if (!ctx || !descriptor)
        return AIRY_ERR_INVALID_PARAM;
    if (ctx->guard_count >= ctx->guard_capacity)
        return AIRY_ERR_FAIL;

    guard_entry_t *entry = &ctx->guards[ctx->guard_count];
    __builtin_memcpy(&entry->descriptor, descriptor, sizeof(*descriptor));
    entry->check_fn = check_fn;
    entry->user_data = user_data;
    ctx->guard_count++;
    return 0;
}

int safety_guard_unregister_guard(safety_guard_context_t *ctx, const char *name)
{
    if (!ctx || !name)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->guard_count; i++) {
        if (__builtin_strcmp(ctx->guards[i].descriptor.name, name) == 0) {
            if (i < ctx->guard_count - 1) {
                __builtin_memmove(&ctx->guards[i], &ctx->guards[i + 1],
                                  (ctx->guard_count - i - 1) * sizeof(guard_entry_t));
            }
            ctx->guard_count--;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

int safety_guard_enable_guard(safety_guard_context_t *ctx, const char *name)
{
    if (!ctx || !name)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->guard_count; i++) {
        if (__builtin_strcmp(ctx->guards[i].descriptor.name, name) == 0) {
            ctx->guards[i].descriptor.enabled = true;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

int safety_guard_disable_guard(safety_guard_context_t *ctx, const char *name)
{
    if (!ctx || !name)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->guard_count; i++) {
        if (__builtin_strcmp(ctx->guards[i].descriptor.name, name) == 0) {
            ctx->guards[i].descriptor.enabled = false;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

size_t safety_guard_get_guard_count(safety_guard_context_t *ctx)
{
    return ctx ? ctx->guard_count : 0;
}

size_t safety_guard_get_policy_count(safety_guard_context_t *ctx)
{
    return ctx ? ctx->policy_count : 0;
}

size_t safety_guard_get_audit_count(safety_guard_context_t *ctx)
{
    return ctx ? ctx->audit_count : 0;
}
