// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_ctrl.c
 * @brief V2 SafetyGuard API 实现 - 回调与紧急停止域
 *
 * 本文件实现违规回调、策略变更回调的注册与紧急停止/解除。
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

int safety_guard_set_violation_callback(safety_guard_context_t *ctx,
                                        safety_violation_callback_t callback, void *user_data)
{
    if (!ctx)
        return AIRY_ERR_INVALID_PARAM;
    ctx->violation_callback = callback;
    ctx->violation_user_data = user_data;
    return 0;
}

int safety_guard_set_policy_change_callback(safety_guard_context_t *ctx,
                                            safety_policy_change_callback_t callback,
                                            void *user_data)
{
    if (!ctx)
        return AIRY_ERR_INVALID_PARAM;
    ctx->policy_change_callback = callback;
    ctx->policy_change_user_data = user_data;
    return 0;
}

int safety_guard_emergency_stop(safety_guard_context_t *ctx, const char *reason)
{
    if (!ctx)
        return AIRY_ERR_INVALID_PARAM;
    ctx->emergency_stopped = true;
    if (reason) {
        snprintf(ctx->emergency_reason, sizeof(ctx->emergency_reason), "%s", reason);
    } else {
        snprintf(ctx->emergency_reason, sizeof(ctx->emergency_reason), "Manual emergency stop");
    }
    return 0;
}

int safety_guard_emergency_release(safety_guard_context_t *ctx)
{
    if (!ctx)
        return AIRY_ERR_INVALID_PARAM;
    ctx->emergency_stopped = false;
    ctx->emergency_reason[0] = '\0';
    return 0;
}
