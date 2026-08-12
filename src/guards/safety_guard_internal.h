// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file safety_guard_internal.h
 * @brief SafetyGuard 模块内部共享定义：上下文结构体与守卫条目
 */

#ifndef AIRY_SAFETY_GUARD_INTERNAL_H
#define AIRY_SAFETY_GUARD_INTERNAL_H

#include "safety_guard.h"

#include "airy_memory.h"
#include "string_compat.h"
#include "config_unified.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    safety_guard_descriptor_t descriptor;
    safety_guard_check_fn check_fn;
    void *user_data;
} guard_entry_t;

struct safety_guard_context_s {
    guard_entry_t *guards;
    size_t guard_count;
    size_t guard_capacity;
    bool initialized;

    safety_audit_entry_t *audit_entries;
    size_t audit_count;
    size_t audit_capacity;

    safety_policy_t *policies;
    size_t policy_count;
    size_t policy_capacity;

    safety_quota_t *quotas;
    size_t quota_count;
    size_t quota_capacity;

    safety_violation_callback_t violation_callback;
    void *violation_user_data;
    safety_policy_change_callback_t policy_change_callback;
    void *policy_change_user_data;

    bool emergency_stopped;
    char emergency_reason[256];
};

#endif /* AIRY_SAFETY_GUARD_INTERNAL_H */
