// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_policy.c
 * @brief V2 SafetyGuard API 实现 - 策略管理域
 *
 * 本文件实现策略的添加/移除/更新/批量加载与冲突仲裁。
 */

#include "safety_guard.h"
#include "safety_guard_internal.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

int safety_guard_add_policy(safety_guard_context_t *ctx, const safety_policy_t *policy)
{
    if (!ctx || !policy)
        return AIRY_ERR_INVALID_PARAM;
    if (ctx->policy_count >= ctx->policy_capacity) {

        size_t new_cap = ctx->policy_capacity * 2;
        safety_policy_t *new_policies =
            (safety_policy_t *)AIRY_REALLOC(ctx->policies, new_cap * sizeof(safety_policy_t));
        if (!new_policies)
            return AIRY_ERR_OUT_OF_MEMORY;
        ctx->policies = new_policies;
        ctx->policy_capacity = new_cap;
    }
    __builtin_memcpy(&ctx->policies[ctx->policy_count], policy, sizeof(*policy));
    if (policy->rules_json) {
        ctx->policies[ctx->policy_count].rules_json = AIRY_STRDUP(policy->rules_json);
    }
    ctx->policy_count++;

    if (ctx->policy_change_callback) {
        ctx->policy_change_callback(policy->id, "added", ctx->policy_change_user_data);
    }
    return 0;
}

int safety_guard_remove_policy(safety_guard_context_t *ctx, const char *policy_id)
{
    if (!ctx || !policy_id)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->policy_count; i++) {
        if (__builtin_strcmp(ctx->policies[i].id, policy_id) == 0) {
            AIRY_FREE(ctx->policies[i].rules_json);
            if (i < ctx->policy_count - 1) {
                __builtin_memmove(&ctx->policies[i], &ctx->policies[i + 1],
                                  (ctx->policy_count - i - 1) * sizeof(safety_policy_t));
            }
            ctx->policy_count--;
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

int safety_guard_update_policy(safety_guard_context_t *ctx, const char *policy_id,
                               const char *new_rules_json)
{
    if (!ctx || !policy_id || !new_rules_json)
        return AIRY_ERR_INVALID_PARAM;
    for (size_t i = 0; i < ctx->policy_count; i++) {
        if (__builtin_strcmp(ctx->policies[i].id, policy_id) == 0) {
            AIRY_FREE(ctx->policies[i].rules_json);
            ctx->policies[i].rules_json = AIRY_STRDUP(new_rules_json);
            return 0;
        }
    }
    return AIRY_ERR_NOT_FOUND;
}

int safety_guard_load_policies(safety_guard_context_t *ctx, const char *policies_json)
{
    if (!ctx || !policies_json)
        return AIRY_ERR_INVALID_PARAM;

    config_context_t *cfg = config_context_create("safety_policies");
    if (!cfg)
        return AIRY_ERR_GENERIC_FAIL;

    config_memory_source_options_t mem_opts = {.data = policies_json,
                                               .data_len = strlen(policies_json),
                                               .format = "json"};
    config_source_t *mem_source = config_source_create_memory(&mem_opts);
    if (!mem_source) {
        config_context_destroy(cfg);
        return AIRY_ERR_GENERIC_FAIL;
    }
    config_error_t err = config_service_load(cfg, &mem_source, 1);
    if (err != CONFIG_SUCCESS) {
        config_context_destroy(cfg);
        return AIRY_ERR_PARSE_ERROR;
    }

    int loaded = 0;
    char key_buf[64];
    for (int i = 0; i < SAFETY_MAX_POLICIES; i++) {
        snprintf(key_buf, sizeof(key_buf), "%d.id", i);
        const config_value_t *id_val = config_context_get(cfg, key_buf);
        if (!id_val)
            break;

        safety_policy_t policy;
        AIRY_MEMSET(&policy, 0, sizeof(policy));

        const char *s = config_value_get_string(id_val, "");
        AIRY_STRNCPY_TERM(policy.id, s, sizeof(policy.id) - 1);

        snprintf(key_buf, sizeof(key_buf), "%d.name", i);
        s = config_value_get_string(config_context_get(cfg, key_buf), "");
        AIRY_STRNCPY_TERM(policy.name, s, sizeof(policy.name) - 1);

        snprintf(key_buf, sizeof(key_buf), "%d.description", i);
        s = config_value_get_string(config_context_get(cfg, key_buf), "");
        AIRY_STRNCPY_TERM(policy.description, s, sizeof(policy.description) - 1);

        snprintf(key_buf, sizeof(key_buf), "%d.default_decision", i);
        policy.default_decision =
            (safety_decision_t)config_value_get_int(config_context_get(cfg, key_buf),
                                                    SAFETY_DECISION_DENY);

        snprintf(key_buf, sizeof(key_buf), "%d.priority", i);
        policy.priority = (safety_priority_t)config_value_get_int(config_context_get(cfg, key_buf),
                                                                  SAFETY_PRIORITY_NORMAL);

        snprintf(key_buf, sizeof(key_buf), "%d.enabled", i);
        policy.enabled = config_value_get_bool(config_context_get(cfg, key_buf), true);

        snprintf(key_buf, sizeof(key_buf), "%d.overridable", i);
        policy.overridable = config_value_get_bool(config_context_get(cfg, key_buf), true);

        snprintf(key_buf, sizeof(key_buf), "%d.rules_json", i);
        const config_value_t *rules_val = config_context_get(cfg, key_buf);
        if (rules_val) {
            policy.rules_json = AIRY_STRDUP(config_value_get_string(rules_val, ""));
        } else {
            policy.rules_json = NULL;
        }

        snprintf(key_buf, sizeof(key_buf), "%d.valid_from", i);
        policy.valid_from = (uint64_t)config_value_get_int(config_context_get(cfg, key_buf), 0);

        snprintf(key_buf, sizeof(key_buf), "%d.valid_until", i);
        policy.valid_until = (uint64_t)config_value_get_int(config_context_get(cfg, key_buf), 0);

        if (safety_guard_add_policy(ctx, &policy) == 0) {
            loaded++;
        }

        if (policy.rules_json) {
            AIRY_FREE(policy.rules_json);
        }
    }

    config_source_destroy(mem_source);
    config_context_destroy(cfg);
    return loaded > 0 ? 0 : AIRY_ERR_GENERIC_FAIL;
}

int safety_guard_resolve_conflict(safety_guard_context_t *ctx, const char *policy_a_id,
                                  const char *policy_b_id, safety_decision_t *resolved_decision)
{
    if (!ctx || !policy_a_id || !policy_b_id || !resolved_decision)
        return AIRY_ERR_INVALID_PARAM;

    safety_policy_t *policy_a = NULL, *policy_b = NULL;
    for (size_t i = 0; i < ctx->policy_count; i++) {
        if (__builtin_strcmp(ctx->policies[i].id, policy_a_id) == 0)
            policy_a = &ctx->policies[i];
        if (__builtin_strcmp(ctx->policies[i].id, policy_b_id) == 0)
            policy_b = &ctx->policies[i];
    }

    if (policy_a && policy_b) {
        if (policy_a->priority >= policy_b->priority) {
            *resolved_decision = policy_a->default_decision;
        } else {
            *resolved_decision = policy_b->default_decision;
        }
    } else if (policy_a) {
        *resolved_decision = policy_a->default_decision;
    } else if (policy_b) {
        *resolved_decision = policy_b->default_decision;
    } else {
        /* Neither policy ID is registered in the context, so the conflict
         * cannot be resolved. The security dome is fail-closed: deny rather
         * than allow, and report the invalid policy IDs to the caller. */
        *resolved_decision = SAFETY_DECISION_DENY;
        return AIRY_ERR_NOT_FOUND;
    }
    return 0;
}
