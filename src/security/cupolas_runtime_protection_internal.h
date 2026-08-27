// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_runtime_protection_internal.h
 * @brief Internal shared declarations for the cupolas_runtime_protection.c
 *        split units (core / memory / check / integrity). Not a public API.
 */

#ifndef CUPOLAS_RUNTIME_PROTECTION_INTERNAL_H
#define CUPOLAS_RUNTIME_PROTECTION_INTERNAL_H

#include "cupolas_runtime_protection.h"

#include "atomic_compat.h"
#include "../platform/platform.h"

#include <stddef.h>
#include <stdint.h>

#define CUPOLAS_MAX_SECCOMP_RULES 256
#define CUPOLAS_MAX_CFI_TARGETS 4096
#define CUPOLAS_MAX_VIOLATION_HISTORY 128

#define RTP_INIT_UNINIT 0
#define RTP_INIT_PROGRESS 1
#define RTP_INIT_COMPLETE 2

typedef struct {
    char *syscall_name;
    int action;
    uint32_t arg_index;
    uint64_t arg_value;
    char op[8];
} seccomp_rule_internal_t;

typedef struct {
    void *source;
    void *target;
    int valid;
} cfi_target_t;

typedef struct {
    cupolas_violation_event_t events[CUPOLAS_MAX_VIOLATION_HISTORY];
    size_t count;
    size_t head;
} violation_history_t;

typedef struct {
    atomic_int initialized;
    cupolas_runtime_protect_config_t manager;
    cupolas_protection_status_t status;

    seccomp_rule_internal_t seccomp_rules[CUPOLAS_MAX_SECCOMP_RULES];
    size_t seccomp_rule_count;
    uint64_t seccomp_allowed_count;
    uint64_t seccomp_denied_count;

    cfi_target_t cfi_targets[CUPOLAS_MAX_CFI_TARGETS];
    size_t cfi_target_count;
    uint64_t cfi_check_count;
    uint64_t cfi_violation_count;

    violation_history_t violations;
    cupolas_protection_stats_t stats;

    uint8_t code_hash[32];
    uint8_t data_hash[32];
    int hashes_computed;

    void (*violation_callback)(const cupolas_violation_event_t *event);
    void (*integrity_callback)(int result);

    cupolas_mutex_t lock;
} cupolas_runtime_prot_state_t;

/* Global protection state, owned by cupolas_runtime_protection.c. */
extern cupolas_runtime_prot_state_t g_runtime_prot;

/* Shared helpers (defined in cupolas_runtime_protection.c). */
uint32_t cupolas_rtp_get_pid(void);
uint32_t cupolas_rtp_get_tid(void);
void cupolas_record_violation(cupolas_violation_type_t type, const char *details,
                              const char *syscall_name);

#endif /* CUPOLAS_RUNTIME_PROTECTION_INTERNAL_H */
