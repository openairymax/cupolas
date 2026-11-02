// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_d_internal.h
 * @brief Internal shared declarations of the cupolas_d daemon translation
 *        units (svc.c / cupolas_rpc_*.c / service.c).
 * @details Single include entry for the cupolas_d translation units
 *          (except the generated main.c assembly unit): aggregates the
 *          generated svc_cupolas_d.h (L3 SSoT, RPC method entry points
 *          m_* and lifecycle hooks) and carries the daemon-wide cupolas
 *          service handle plus the dynamic policy engine (PDP) handle.
 *          For use only by the cupolas_d daemon translation units.
 */

#ifndef AIRY_RT_DAEMON_CUPOLAS_D_INTERNAL_H
#define AIRY_RT_DAEMON_CUPOLAS_D_INTERNAL_H

#include "cupolas_service.h"
#include "svc_cupolas_d.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Daemon-wide cupolas service handle (owned/lifecycled in svc.c,
 * referenced by the JSON-RPC handlers). */
extern cupolas_service_t *g_service;

/* Dynamic policy engine handle (PDP, owned/lifecycled in svc.c,
 * referenced by the policy RPC handlers). */
extern struct dpolicy_engine_s *g_dpolicy;

/* Canary governor lifecycle (svc_canary.c): mounts the canary ops onto
 * g_dpolicy and drives the five-state reconciliation tick. Absent ops
 * mean full bypass; on() failure is non-fatal by design. */
int svc_canary_on(void);
void svc_canary_off(void);

/* Read-only K1/K2 snapshot for policy.canary: the governor owns the only
 * aggregated observation samples, so the RPC layer must not recompute
 * them. stat() returning -1 means the governor is unmounted (bypass). */
typedef struct {
    const char *state;
    const char *gate;
    int ks_hit;
    unsigned permille;
    uint64_t samples;
    uint64_t diverge;
    uint32_t ok_pm;
    uint32_t perf_ppm;
    uint32_t rb_secs;
    uint64_t routed_total;
    uint64_t routed_picked;
} svc_canary_snap_t;

int svc_canary_stat(svc_canary_snap_t *out);

#ifdef __cplusplus
}
#endif

#endif /* AIRY_RT_DAEMON_CUPOLAS_D_INTERNAL_H */
