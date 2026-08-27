// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_runtime_protection_check.c
 * @brief Enhanced Runtime Protection - policy check domain: CFI target
 *        registration / verification and seccomp syscall policy rules
 *        (functional domain after cupolas_runtime_protection.c split).
 * @author SPHARX Ltd. - Airymax Team
 * @date 2026
 */

#include "cupolas_runtime_protection.h"
#include "cupolas_runtime_protection_internal.h"

#include "../platform/platform.h"
#include "string_compat.h"

#include <string.h>

#ifndef _WIN32
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#include "error.h"

int cupolas_cfi_enable(const cupolas_cfi_config_t *manager)
{
    if (!manager)
        return AIRY_EINVAL;

    g_runtime_prot.cfi_target_count = 0;
    g_runtime_prot.cfi_check_count = 0;
    g_runtime_prot.cfi_violation_count = 0;

    return 0;
}

int cupolas_cfi_register_target(void *source, void *target)
{
    if (!source || !target)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    if (g_runtime_prot.cfi_target_count >= CUPOLAS_MAX_CFI_TARGETS) {
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return AIRY_EINVAL;
    }

    cfi_target_t *entry = &g_runtime_prot.cfi_targets[g_runtime_prot.cfi_target_count];
    entry->source = source;
    entry->target = target;
    entry->valid = 1;
    g_runtime_prot.cfi_target_count++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return 0;
}

int cupolas_cfi_verify_transfer(void *source, void *target)
{
    if (!source || !target)
        return 0;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.cfi_check_count++;
    g_runtime_prot.stats.total_checks++;

    for (size_t i = 0; i < g_runtime_prot.cfi_target_count; i++) {
        cfi_target_t *entry = &g_runtime_prot.cfi_targets[i];
        if (entry->source == source && entry->target == target && entry->valid) {
            cupolas_mutex_unlock(&g_runtime_prot.lock);
            return 1;
        }
    }

    g_runtime_prot.cfi_violation_count++;
    g_runtime_prot.stats.cfi_violations++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    cupolas_record_violation(CUPOLAS_VIOLATION_CONTROL_FLOW, "Invalid control flow transfer", NULL);

    return 0;
}

int cupolas_cfi_get_stats(uint64_t *checks, uint64_t *violations)
{
    if (!checks || !violations)
        return AIRY_EINVAL;
    cupolas_mutex_lock(&g_runtime_prot.lock);
    *checks = g_runtime_prot.cfi_check_count;
    *violations = g_runtime_prot.cfi_violation_count;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}

int cupolas_seccomp_enable(const cupolas_seccomp_config_t *manager)
{
    if (!manager)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.seccomp_rule_count = 0;
    g_runtime_prot.seccomp_allowed_count = 0;
    g_runtime_prot.seccomp_denied_count = 0;

    if (manager->allowed_syscalls) {
        for (size_t i = 0; i < manager->syscall_count &&
                           g_runtime_prot.seccomp_rule_count < CUPOLAS_MAX_SECCOMP_RULES;
             i++) {
            seccomp_rule_internal_t *rule =
                &g_runtime_prot.seccomp_rules[g_runtime_prot.seccomp_rule_count];
            rule->syscall_name = cupolas_strdup(manager->allowed_syscalls[i]);
            rule->action = 0;
            rule->arg_index = 0;
            rule->arg_value = 0;
            rule->op[0] = '\0';
            g_runtime_prot.seccomp_rule_count++;
        }
    }
    cupolas_mutex_unlock(&g_runtime_prot.lock);

#ifdef __linux__
#ifdef PR_SET_NO_NEW_PRIVS
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return AIRY_EINVAL;
    }
#endif
#endif

    return 0;
}

int cupolas_seccomp_allow(const char *syscall_name)
{
    if (!syscall_name)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    if (g_runtime_prot.seccomp_rule_count >= CUPOLAS_MAX_SECCOMP_RULES) {
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return AIRY_EINVAL;
    }

    seccomp_rule_internal_t *rule =
        &g_runtime_prot.seccomp_rules[g_runtime_prot.seccomp_rule_count];
    rule->syscall_name = cupolas_strdup(syscall_name);
    rule->action = 0;
    rule->arg_index = 0;
    rule->arg_value = 0;
    rule->op[0] = '\0';
    g_runtime_prot.seccomp_rule_count++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return 0;
}

int cupolas_seccomp_deny(const char *syscall_name)
{
    if (!syscall_name)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    if (g_runtime_prot.seccomp_rule_count >= CUPOLAS_MAX_SECCOMP_RULES) {
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return AIRY_EINVAL;
    }

    seccomp_rule_internal_t *rule =
        &g_runtime_prot.seccomp_rules[g_runtime_prot.seccomp_rule_count];
    rule->syscall_name = cupolas_strdup(syscall_name);
    rule->action = 1;
    rule->arg_index = 0;
    rule->arg_value = 0;
    rule->op[0] = '\0';
    g_runtime_prot.seccomp_rule_count++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return 0;
}

int cupolas_seccomp_add_rule(const char *syscall_name, uint32_t arg_index, const char *op,
                             uint64_t value, int action)
{
    if (!syscall_name || !op)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    if (g_runtime_prot.seccomp_rule_count >= CUPOLAS_MAX_SECCOMP_RULES) {
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return AIRY_EINVAL;
    }

    seccomp_rule_internal_t *rule =
        &g_runtime_prot.seccomp_rules[g_runtime_prot.seccomp_rule_count];
    rule->syscall_name = cupolas_strdup(syscall_name);
    rule->action = action;
    rule->arg_index = arg_index;
    rule->arg_value = value;
    AIRY_STRNCPY_TERM(rule->op, op, sizeof(rule->op));
    rule->op[sizeof(rule->op) - 1] = '\0';
    g_runtime_prot.seccomp_rule_count++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return 0;
}

int cupolas_seccomp_check(const char *syscall_name)
{
    if (!syscall_name)
        return 0;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.stats.total_checks++;

    for (size_t i = 0; i < g_runtime_prot.seccomp_rule_count; i++) {
        seccomp_rule_internal_t *rule = &g_runtime_prot.seccomp_rules[i];
        if (strcmp(rule->syscall_name, syscall_name) == 0) {
            if (rule->action == 0) {
                g_runtime_prot.seccomp_allowed_count++;
                cupolas_mutex_unlock(&g_runtime_prot.lock);
                return 1;
            } else {
                g_runtime_prot.seccomp_denied_count++;
                g_runtime_prot.stats.syscall_denied++;
                cupolas_mutex_unlock(&g_runtime_prot.lock);
                cupolas_record_violation(CUPOLAS_VIOLATION_SYSCALL, "Blocked syscall",
                                         syscall_name);
                return 0;
            }
        }
    }

    if (g_runtime_prot.manager.seccomp.default_action == 0) {
        g_runtime_prot.seccomp_allowed_count++;
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return 1;
    }

    g_runtime_prot.seccomp_denied_count++;
    g_runtime_prot.stats.syscall_denied++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    cupolas_record_violation(CUPOLAS_VIOLATION_SYSCALL, "Default deny", syscall_name);
    return 0;
}

int cupolas_seccomp_get_stats(uint64_t *allowed, uint64_t *denied)
{
    if (!allowed || !denied)
        return AIRY_EINVAL;
    cupolas_mutex_lock(&g_runtime_prot.lock);
    *allowed = g_runtime_prot.seccomp_allowed_count;
    *denied = g_runtime_prot.seccomp_denied_count;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}
