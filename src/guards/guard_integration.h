/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file guard_integration.h
 * @brief SafetyGuard integration with Cupolas components.
 *
 * Integration API between the SafetyGuard framework and the existing
 * Cupolas components.
 */

#ifndef CUPOLAS_GUARD_INTEGRATION_H
#define CUPOLAS_GUARD_INTEGRATION_H

#include "guard_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */

/* ============================================================================ */
/**
 * @brief Initialize the Cupolas guard integration
 * @param config Guard manager configuration
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_init(const guard_manager_config_t *config);

/**
 * @brief Clean up the Cupolas guard integration
 */
CUPOLAS_API void cupolas_guards_cleanup(void);

/**
 * @brief Enable guards
 */
CUPOLAS_API void cupolas_guards_enable(void);

/**
 * @brief Disable guards
 */
CUPOLAS_API void cupolas_guards_disable(void);

/**
 * @brief Check whether guards are enabled
 * @return 1 if enabled, 0 if disabled
 */
CUPOLAS_API int cupolas_guards_is_enabled(void);

/**
 * @brief Get the guard manager instance
 * @return Guard manager handle
 */
CUPOLAS_API guard_manager_t *cupolas_guards_get_manager(void);

/**
 * @brief Register a guard with Cupolas
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_register_guard(guard_t *guard);

/**
 * @brief Run security checks (for Cupolas operations)
 * @param operation Operation name
 * @param resource Resource identifier
 * @param agent_id Agent ID
 * @param input_data Input data
 * @param input_size Input data size
 * @param results Result array (output)
 * @param max_results Maximum number of results
 * @param actual_results Actual number of results (output)
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_check(const char *operation, const char *resource,
                                     const char *agent_id, const void *input_data,
                                     size_t input_size, guard_result_t *results, size_t max_results,
                                     size_t *actual_results);

/**
 * @brief Register the Cupolas hooks
 *
 * Registers the guard hooks into the Cupolas components.
 * Note: must be called after Cupolas initialization.
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_register_hooks(void);

/**
 * @brief Unregister the Cupolas hooks
 */
CUPOLAS_API void cupolas_guards_unregister_hooks(void);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_GUARD_INTEGRATION_H */