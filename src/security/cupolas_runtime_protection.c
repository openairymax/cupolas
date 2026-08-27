// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_runtime_protection.c - Enhanced Runtime Protection core lifecycle
 */

/**
 * @file cupolas_runtime_protection.c
 * @brief Enhanced Runtime Protection - core lifecycle (init / cleanup /
 *        enable / disable / status) and shared violation recording.
 *        Policy units split into cupolas_runtime_protection_memory.c,
 *        cupolas_runtime_protection_check.c and
 *        cupolas_runtime_protection_integrity.c.
 * @author SPHARX Ltd. - Airymax Team
 * @date 2026
 */

#include "cupolas_runtime_protection.h"
#include "cupolas_runtime_protection_internal.h"

#include "../platform/platform.h"
#include "atomic_compat.h"
#include "airy_memory.h"
#include "string_compat.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#endif

#include "error.h"

cupolas_runtime_prot_state_t g_runtime_prot;

uint32_t cupolas_rtp_get_pid(void)
{
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

uint32_t cupolas_rtp_get_tid(void)
{
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return (uint32_t)pthread_self();
#endif
}

void cupolas_record_violation(cupolas_violation_type_t type, const char *details,
                              const char *syscall_name)
{
    cupolas_mutex_lock(&g_runtime_prot.lock);

    if (g_runtime_prot.violations.count >= CUPOLAS_MAX_VIOLATION_HISTORY) {
        g_runtime_prot.violations.head =
            (g_runtime_prot.violations.head + 1) % CUPOLAS_MAX_VIOLATION_HISTORY;
    }

    size_t idx = (g_runtime_prot.violations.head + g_runtime_prot.violations.count) %
                 CUPOLAS_MAX_VIOLATION_HISTORY;
    if (g_runtime_prot.violations.count < CUPOLAS_MAX_VIOLATION_HISTORY) {
        g_runtime_prot.violations.count++;
    }

    cupolas_violation_event_t *event = &g_runtime_prot.violations.events[idx];
    event->type = type;
    event->timestamp = cupolas_time_ms();
    event->pid = cupolas_rtp_get_pid();
    event->tid = cupolas_rtp_get_tid();
    if (event->details) {
        AIRY_FREE(event->details);
        event->details = NULL;
    }
    event->details = details ? cupolas_strdup(details) : NULL;
    if (event->syscall_name) {
        AIRY_FREE(event->syscall_name);
        event->syscall_name = NULL;
    }
    event->syscall_name = syscall_name ? cupolas_strdup(syscall_name) : NULL;
    event->fault_address = NULL;
    event->error_code = 0;

    g_runtime_prot.stats.violations_detected++;

    void (*cb)(const cupolas_violation_event_t *) = g_runtime_prot.violation_callback;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    if (cb) {
        cb(event);
    }
}

int cupolas_runtime_protect_init(const cupolas_runtime_protect_config_t *manager)
{
    if (atomic_load(&g_runtime_prot.initialized) == RTP_INIT_COMPLETE)
        return 0;

    int expected = RTP_INIT_UNINIT;
    if (atomic_compare_exchange_strong(&g_runtime_prot.initialized, &expected, RTP_INIT_PROGRESS)) {
        AIRY_MEMSET(&g_runtime_prot, 0, sizeof(g_runtime_prot));

        cupolas_mutex_init(&g_runtime_prot.lock);

        if (manager) {
            g_runtime_prot.manager = *manager;
        } else {
            g_runtime_prot.manager.level = CUPOLAS_PROTECT_BASIC;
            g_runtime_prot.manager.memory.enable_aslr = true;
            g_runtime_prot.manager.memory.enable_dep = true;
            g_runtime_prot.manager.seccomp.default_action = 0;
            g_runtime_prot.manager.integrity.check_interval_ms = 60000;
            g_runtime_prot.manager.enable_audit = true;
        }

        g_runtime_prot.status = CUPOLAS_PROTECT_STATUS_INACTIVE;

        atomic_store(&g_runtime_prot.initialized, RTP_INIT_COMPLETE);
        return 0;
    }

    while (atomic_load(&g_runtime_prot.initialized) != RTP_INIT_COMPLETE) {
        sched_yield();
    }
    return 0;
}

void cupolas_runtime_protect_cleanup(void)
{
    if (atomic_load(&g_runtime_prot.initialized) != RTP_INIT_COMPLETE)
        return;

    for (size_t i = 0; i < g_runtime_prot.seccomp_rule_count; i++) {
        AIRY_FREE(g_runtime_prot.seccomp_rules[i].syscall_name);
    }

    for (size_t i = 0; i < CUPOLAS_MAX_VIOLATION_HISTORY; i++) {
        AIRY_FREE(g_runtime_prot.violations.events[i].details);
        AIRY_FREE(g_runtime_prot.violations.events[i].syscall_name);
    }

    CUPOLAS_MUTEX_DESTROY(&g_runtime_prot.lock);

    AIRY_MEMSET(&g_runtime_prot, 0, sizeof(g_runtime_prot));
}

int cupolas_runtime_protect_enable(const cupolas_runtime_protect_config_t *manager)
{
    if (atomic_load(&g_runtime_prot.initialized) != RTP_INIT_COMPLETE) {
        int result = cupolas_runtime_protect_init(manager);
        if (result != 0)
            return result;
    } else if (manager) {
        cupolas_mutex_lock(&g_runtime_prot.lock);
        g_runtime_prot.manager = *manager;
        cupolas_mutex_unlock(&g_runtime_prot.lock);
    }

    if (g_runtime_prot.manager.memory.enable_dep || g_runtime_prot.manager.memory.enable_aslr) {
        int result = cupolas_memory_protect_enable(&g_runtime_prot.manager.memory);
        if (result != 0)
            return result;
    }

    if (g_runtime_prot.manager.cfi.enable_cfi) {
        int result = cupolas_cfi_enable(&g_runtime_prot.manager.cfi);
        if (result != 0)
            return result;
    }

    if (g_runtime_prot.manager.seccomp.enable_seccomp) {
        int result = cupolas_seccomp_enable(&g_runtime_prot.manager.seccomp);
        if (result != 0)
            return result;
    }

    if (g_runtime_prot.manager.integrity.enable_code_integrity ||
        g_runtime_prot.manager.integrity.enable_data_integrity) {
        int result = cupolas_integrity_enable(&g_runtime_prot.manager.integrity);
        if (result != 0)
            return result;
    }

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.status = CUPOLAS_PROTECT_STATUS_ACTIVE;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}

int cupolas_runtime_protect_disable(void)
{
    if (atomic_load(&g_runtime_prot.initialized) != RTP_INIT_COMPLETE)
        return AIRY_EINVAL;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.status = CUPOLAS_PROTECT_STATUS_INACTIVE;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}

cupolas_protection_status_t cupolas_runtime_protect_get_status(void)
{
    cupolas_mutex_lock(&g_runtime_prot.lock);
    cupolas_protection_status_t status = g_runtime_prot.status;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return status;
}

int cupolas_runtime_protect_get_config(cupolas_runtime_protect_config_t *manager)
{
    if (!manager)
        return AIRY_EINVAL;
    cupolas_mutex_lock(&g_runtime_prot.lock);
    *manager = g_runtime_prot.manager;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}

const char *cupolas_protection_level_string(cupolas_protection_level_t level)
{
    switch (level) {
    case CUPOLAS_PROTECT_NONE:
        return "None";
    case CUPOLAS_PROTECT_BASIC:
        return "Basic";
    case CUPOLAS_PROTECT_ENHANCED:
        return "Enhanced";
    case CUPOLAS_PROTECT_MAXIMUM:
        return "Maximum";
    default:
        return "Unknown";
    }
}

const char *cupolas_protection_status_string(cupolas_protection_status_t status)
{
    switch (status) {
    case CUPOLAS_PROTECT_STATUS_INACTIVE:
        return "Inactive";
    case CUPOLAS_PROTECT_STATUS_ACTIVE:
        return "Active";
    case CUPOLAS_PROTECT_STATUS_VIOLATION:
        return "Violation";
    case CUPOLAS_PROTECT_STATUS_COMPROMISED:
        return "Compromised";
    default:
        return "Unknown";
    }
}

const char *cupolas_violation_type_string(cupolas_violation_type_t type)
{
    switch (type) {
    case CUPOLAS_VIOLATION_NONE:
        return "None";
    case CUPOLAS_VIOLATION_SYSCALL:
        return "Syscall Violation";
    case CUPOLAS_VIOLATION_MEMORY:
        return "Memory Violation";
    case CUPOLAS_VIOLATION_CONTROL_FLOW:
        return "Control Flow Violation";
    case CUPOLAS_VIOLATION_INTEGRITY:
        return "Integrity Violation";
    case CUPOLAS_VIOLATION_RESOURCE:
        return "Resource Violation";
    default:
        return "Unknown";
    }
}

bool cupolas_protection_is_supported(const char *feature)
{
    if (!feature)
        return false;

#ifdef __linux__
    if (strcmp(feature, "seccomp") == 0)
        return true;
    if (strcmp(feature, "aslr") == 0)
        return true;
    if (strcmp(feature, "dep") == 0)
        return true;
#endif

#ifdef _WIN32
    if (strcmp(feature, "dep") == 0)
        return true;
    if (strcmp(feature, "aslr") == 0)
        return true;
#endif

    if (strcmp(feature, "cfi") == 0)
        return true;
    if (strcmp(feature, "integrity") == 0)
        return true;

    return false;
}

int cupolas_protection_get_capabilities(char ***capabilities, size_t *count)
{
    if (!capabilities || !count)
        return AIRY_EINVAL;

    static const char *caps[] = {"integrity", "cfi",
#ifdef __linux__
                                 "seccomp",
#endif
                                 "aslr", "dep"};

    *count = sizeof(caps) / sizeof(caps[0]);
    SAFE_MALLOC_ARRAY(*capabilities, *count, sizeof(char *));

    for (size_t i = 0; i < *count; i++) {
        (*capabilities)[i] = cupolas_strdup(caps[i]);
    }

    return 0;
}
