// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_check.c
 * @brief V2 SafetyGuard API 实现 - 规则匹配与策略执行域
 *
 * 本文件实现 6 种默认守卫检查（权限/速率/内容/输入/资源/审计）、
 * 默认检查函数分派，以及守卫链执行（check / check_chain / check_permission）。
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief 默认权限检查（SAFETY_GUARD_PERMISSION）
 * 检查 agent_id 是否有权限执行指定操作
 */
static safety_decision_t default_permission_check(const safety_guard_descriptor_t *guard,
                                                  const safety_event_t *event,
                                                  safety_result_t *result)
{
    (void)guard;

    if (event->subject[0] == '\0' || event->action[0] == '\0') {
        if (result) {
            result->decision = SAFETY_DECISION_DENY;
            snprintf(result->reason, sizeof(result->reason),
                     "Permission denied: empty subject or action");
            result->severity = SAFETY_SEVERITY_ERROR;
        }
        return SAFETY_DECISION_DENY;
    }

    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Permission granted: %s → %s",
                 event->subject, event->action);
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

/**
 * @brief 默认速率限制检查（SAFETY_GUARD_RATE_LIMIT）
 * 基于注册的配额系统检查工具调用频率。
 * 具体限制通过 safety_guard_set_quota() 为每个 agent 单独配置。
 * 此默认实现检查 event->flags 中的频控标记位。
 */
static safety_decision_t default_rate_limit_check(const safety_guard_descriptor_t *guard,
                                                  const safety_event_t *event,
                                                  safety_result_t *result)
{
    (void)guard;
    if (event->flags & 0x01) { /* RATE_LIMITED flag */
        if (result) {
            result->decision = SAFETY_DECISION_DENY;
            snprintf(result->reason, sizeof(result->reason), "Rate limit exceeded for %s",
                     event->subject);
            result->severity = SAFETY_SEVERITY_WARNING;
        }
        return SAFETY_DECISION_DENY;
    }
    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Rate limit OK for %s", event->subject);
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

/**
 * @brief 默认内容过滤检查（SAFETY_GUARD_CONTENT_FILTER）
 * 检查输入内容是否包含敏感/危险模式
 */
static safety_decision_t default_content_filter_check(const safety_guard_descriptor_t *guard,
                                                      const safety_event_t *event,
                                                      safety_result_t *result)
{
    (void)guard;

    if (event->context && event->context_size > 0) {
        const char *content = (const char *)event->context;

        static const char *dangerous_patterns[] = {"rm -rf /",  "DROP TABLE",  "DELETE FROM",
                                                   "shutdown",  "format c:",   "wget http",
                                                   "curl http", "/etc/passwd", NULL};
        for (int i = 0; dangerous_patterns[i]; i++) {
            if (strstr(content, dangerous_patterns[i])) {
                if (result) {
                    result->decision = SAFETY_DECISION_DENY;
                    snprintf(result->reason, sizeof(result->reason),
                             "Content filter: dangerous pattern '%s' detected",
                             dangerous_patterns[i]);
                    result->severity = SAFETY_SEVERITY_ERROR;
                }
                return SAFETY_DECISION_DENY;
            }
        }
    }
    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Content filter passed");
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

/**
 * @brief 默认输入检查（SAFETY_GUARD_INPUT）
 * 检查输入参数的合法性
 */
static safety_decision_t default_input_check(const safety_guard_descriptor_t *guard,
                                             const safety_event_t *event, safety_result_t *result)
{
    (void)guard;

    if (event->context_size > (1024 * 1024)) {
        if (result) {
            result->decision = SAFETY_DECISION_DENY;
            snprintf(result->reason, sizeof(result->reason), "Input too large: %zu bytes",
                     event->context_size);
            result->severity = SAFETY_SEVERITY_ERROR;
        }
        return SAFETY_DECISION_DENY;
    }
    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Input validation passed");
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

/**
 * @brief 默认资源检查（SAFETY_GUARD_RESOURCE）
 *
 * 基于事件数据进行资源验证：
 * 1. 检查 event->flags 中的资源耗尽标志位（bit 1 = RESOURCE_EXHAUSTED）
 * 2. 检查 context_size 是否超过单次资源操作上限（100MB）
 * 3. 检查 resource 字段是否为已知受限资源
 *
 * 注意：默认检查函数签名不含 context，无法访问 ctx->quotas。
 * 精确配额检查通过 safety_guard_check_quota() API 或注册自定义
 * check_fn（将 ctx 作为 user_data 传入）实现。
 */
static safety_decision_t default_resource_check(const safety_guard_descriptor_t *guard,
                                                const safety_event_t *event,
                                                safety_result_t *result)
{
    (void)guard;

    if (event->flags & 0x02) {
        if (result) {
            result->decision = SAFETY_DECISION_DENY;
            snprintf(result->reason, sizeof(result->reason),
                     "Resource exhausted: %s flagged as over limit", event->resource);
            result->severity = SAFETY_SEVERITY_ERROR;
        }
        return SAFETY_DECISION_DENY;
    }

    const size_t MAX_RESOURCE_OP_SIZE = 100 * 1024 * 1024;
    if (event->context_size > MAX_RESOURCE_OP_SIZE) {
        if (result) {
            result->decision = SAFETY_DECISION_DENY;
            snprintf(result->reason, sizeof(result->reason),
                     "Resource operation too large: %zu bytes (max %zu)", event->context_size,
                     MAX_RESOURCE_OP_SIZE);
            result->severity = SAFETY_SEVERITY_ERROR;
        }
        return SAFETY_DECISION_DENY;
    }

    if (event->resource[0] != '\0') {
        static const char *restricted_resources[] = {"/proc/kcore", "/dev/mem", "/dev/kmem",
                                                     "/dev/port", NULL};
        for (int i = 0; restricted_resources[i]; i++) {
            if (strstr(event->resource, restricted_resources[i])) {
                if (result) {
                    result->decision = SAFETY_DECISION_DENY;
                    snprintf(result->reason, sizeof(result->reason),
                             "Resource access denied: '%s' is restricted", restricted_resources[i]);
                    result->severity = SAFETY_SEVERITY_ERROR;
                }
                return SAFETY_DECISION_DENY;
            }
        }
    }

    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Resource check passed for %s",
                 event->resource[0] ? event->resource : "(none)");
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

/**
 * @brief 默认审计检查（SAFETY_GUARD_AUDIT）
 *
 * 审计守卫的设计语义：审计不阻止操作，只记录事件。
 * 实际的审计日志写入由编排函数（safety_guard_check / check_chain）
 * 在调用本函数后通过 safety_guard_record_audit() 完成。
 *
 * 本函数的职责：
 * 1. 验证事件具有审计所需的最小元数据（subject + action）
 * 2. 标记审计结果，供编排函数记录
 * 3. 始终返回 ALLOW（审计不阻断业务流）
 */
static safety_decision_t default_audit_check(const safety_guard_descriptor_t *guard,
                                             const safety_event_t *event, safety_result_t *result)
{
    (void)guard;

    if (event->subject[0] == '\0' || event->action[0] == '\0') {
        if (result) {
            result->decision = SAFETY_DECISION_ALLOW;
            snprintf(result->reason, sizeof(result->reason),
                     "Audit warning: incomplete event metadata (subject/action empty)");
            result->severity = SAFETY_SEVERITY_WARNING;
        }
        return SAFETY_DECISION_ALLOW;
    }

    if (result) {
        result->decision = SAFETY_DECISION_ALLOW;
        snprintf(result->reason, sizeof(result->reason), "Audit: event recorded for %s → %s",
                 event->subject, event->action);
        result->severity = SAFETY_SEVERITY_INFO;
    }
    return SAFETY_DECISION_ALLOW;
}

typedef safety_decision_t (*default_check_fn_t)(const safety_guard_descriptor_t *,
                                                const safety_event_t *, safety_result_t *);

static default_check_fn_t get_default_check_fn(safety_guard_type_t type)
{
    switch (type) {
    case SAFETY_GUARD_PERMISSION:
        return default_permission_check;
    case SAFETY_GUARD_RATE_LIMIT:
        return default_rate_limit_check;
    case SAFETY_GUARD_CONTENT_FILTER:
        return default_content_filter_check;
    case SAFETY_GUARD_INPUT:
        return default_input_check;
    case SAFETY_GUARD_RESOURCE:
        return default_resource_check;
    case SAFETY_GUARD_AUDIT:
        return default_audit_check;
    default:
        return NULL;
    }
}

safety_decision_t safety_guard_check(safety_guard_context_t *ctx, const safety_event_t *event,
                                     safety_result_t *result)
{
    if (!ctx || !event) {
        if (result) {
            __builtin_memset(result, 0, sizeof(*result));
            result->decision = SAFETY_DECISION_DENY;
        }
        return SAFETY_DECISION_DENY;
    }

    if (ctx->emergency_stopped) {
        if (result) {
            result->decision = SAFETY_DECISION_ABORT;
            snprintf(result->reason, sizeof(result->reason), "Emergency stop: %s",
                     ctx->emergency_reason);
            result->severity = SAFETY_SEVERITY_FATAL;
        }
        return SAFETY_DECISION_ABORT;
    }

    safety_decision_t final_decision = SAFETY_DECISION_ALLOW;

    for (size_t i = 0; i < ctx->guard_count; i++) {
        guard_entry_t *entry = &ctx->guards[i];
        if (!entry->descriptor.enabled)
            continue;

        safety_result_t guard_result;
        __builtin_memset(&guard_result, 0, sizeof(guard_result));

        safety_decision_t decision;
        if (entry->check_fn) {
            decision = entry->check_fn(&entry->descriptor, event, &guard_result, entry->user_data);
        } else {

            default_check_fn_t default_fn = get_default_check_fn(entry->descriptor.type);
            if (default_fn) {
                decision = default_fn(&entry->descriptor, event, &guard_result);
            } else {
                guard_result.decision = SAFETY_DECISION_ALLOW;
                decision = SAFETY_DECISION_ALLOW;
            }
        }

        if (entry->descriptor.audit_enabled) {
            safety_guard_record_audit(ctx, event, &guard_result, entry->descriptor.name);
        }

        if (decision == SAFETY_DECISION_DENY || decision == SAFETY_DECISION_ABORT) {
            final_decision = decision;
            if (result) {
                __builtin_memcpy(result, &guard_result, sizeof(*result));
            }

            if (ctx->violation_callback) {
                ctx->violation_callback(event, &guard_result, ctx->violation_user_data);
            }
            break;
        }

        if (decision == SAFETY_DECISION_CONDITIONAL && final_decision == SAFETY_DECISION_ALLOW) {
            final_decision = SAFETY_DECISION_CONDITIONAL;
        }
    }

    if (result && final_decision != SAFETY_DECISION_DENY &&
        final_decision != SAFETY_DECISION_ABORT) {
        __builtin_memset(result, 0, sizeof(*result));
        result->decision = final_decision;
        result->severity = SAFETY_SEVERITY_INFO;
    }

    return final_decision;
}

safety_decision_t safety_guard_check_chain(safety_guard_context_t *ctx, const safety_event_t *event,
                                           safety_result_t **results, size_t *result_count)
{
    if (!ctx || !event) {
        if (results && result_count) {
            *result_count = 0;
            *results = NULL;
        }
        return SAFETY_DECISION_DENY;
    }

    if (ctx->emergency_stopped) {
        if (results && result_count) {
            *result_count = 0;
            *results = NULL;
        }
        return SAFETY_DECISION_ABORT;
    }

    size_t count = ctx->guard_count;
    if (count == 0) {
        if (results && result_count) {
            *result_count = 0;
            *results = NULL;
        }
        return SAFETY_DECISION_ALLOW;
    }

    safety_result_t *out_results = (safety_result_t *)AIRY_CALLOC(count, sizeof(safety_result_t));
    if (!out_results) {
        if (results && result_count) {
            *result_count = 0;
            *results = NULL;
        }
        return SAFETY_DECISION_ALLOW;
    }

    safety_decision_t final_decision = SAFETY_DECISION_ALLOW;
    size_t actual_count = 0;

    for (int prio = SAFETY_PRIORITY_CRITICAL; prio >= SAFETY_PRIORITY_LOWEST; prio--) {
        for (size_t i = 0; i < ctx->guard_count; i++) {
            guard_entry_t *entry = &ctx->guards[i];
            if (!entry->descriptor.enabled)
                continue;
            if ((int)entry->descriptor.priority != prio)
                continue;

            safety_result_t *guard_result = &out_results[actual_count];

            safety_decision_t decision;
            if (entry->check_fn) {
                decision =
                    entry->check_fn(&entry->descriptor, event, guard_result, entry->user_data);
            } else {
                default_check_fn_t default_fn = get_default_check_fn(entry->descriptor.type);
                if (default_fn) {
                    decision = default_fn(&entry->descriptor, event, guard_result);
                } else {
                    guard_result->decision = SAFETY_DECISION_ALLOW;
                    decision = SAFETY_DECISION_ALLOW;
                }
            }

            actual_count++;

            if (entry->descriptor.audit_enabled) {
                safety_guard_record_audit(ctx, event, guard_result, entry->descriptor.name);
            }

            if (decision == SAFETY_DECISION_DENY || decision == SAFETY_DECISION_ABORT) {
                final_decision = decision;

                if (ctx->violation_callback) {
                    ctx->violation_callback(event, guard_result, ctx->violation_user_data);
                }

                if (entry->descriptor.blocking) {
                    goto chain_done;
                }
            }

            if (decision == SAFETY_DECISION_CONDITIONAL &&
                final_decision == SAFETY_DECISION_ALLOW) {
                final_decision = SAFETY_DECISION_CONDITIONAL;
            }
        }
    }

chain_done:
    if (results) {
        *results = out_results;
    } else {
        AIRY_FREE(out_results);
    }
    if (result_count) {
        *result_count = actual_count;
    }

    return final_decision;
}

int safety_guard_check_permission(safety_guard_context_t *ctx, safety_guard_type_t guard_type,
                                  const char *agent_id, bool *allowed)
{
    if (!ctx || !agent_id || !allowed)
        return AIRY_ERR_INVALID_PARAM;

    safety_event_t event;
    __builtin_memset(&event, 0, sizeof(event));
    event.type = SAFETY_EVENT_ACCESS_REQUEST;
    snprintf(event.subject, sizeof(event.subject), "%s", agent_id);
    snprintf(event.action, sizeof(event.action), "check_permission");

    safety_result_t result;
    safety_decision_t decision = safety_guard_check(ctx, &event, &result);

    *allowed = (decision == SAFETY_DECISION_ALLOW || decision == SAFETY_DECISION_CONDITIONAL);
    return 0;
}
