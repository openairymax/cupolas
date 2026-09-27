// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file guard_integration.c
 * @brief SafetyGuard integration with Cupolas components.
 *
 * Provides the guard manager lifecycle and the explicit security-check
 * entry point (cupolas_guards_check) for Cupolas operations.
 */

#include "../../include/cupolas.h"
#include "../audit/audit.h"
#include "../utils/cupolas_utils.h"
#include "guard_core.h"
#include "platform.h"
#include "airy_memory.h"

#include <stdlib.h>
#include <string.h>

// ============================================================================
// ============================================================================

static guard_manager_t *g_guard_manager = NULL;
static bool g_guards_enabled = false;
static audit_logger_t *g_guard_audit_logger = NULL;
static char g_current_agent_id[64] = "system";

// ============================================================================
// ============================================================================

/**
 * @brief Initialize the Cupolas guard integration
 * @param config Guard manager configuration
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_init(const guard_manager_config_t *config)
{
    if (g_guard_manager) {
        return cupolas_ERROR_BUSY;
    }

    g_guard_manager = guard_manager_create(config);
    if (!g_guard_manager) {
        return cupolas_ERROR_NO_MEMORY;
    }

    g_guards_enabled = true;

    if (!g_guard_audit_logger) {
        g_guard_audit_logger =
            audit_logger_create(AIRY_TMP_DIR "/cupolas_audit", "guard", 1024 * 1024, 10);
    }

    return CUPOLAS_OK;
}

/**
 * @brief Clean up the Cupolas guard integration
 */
CUPOLAS_API void cupolas_guards_cleanup(void)
{
    if (g_guard_audit_logger) {
        audit_logger_flush(g_guard_audit_logger);
        audit_logger_destroy(g_guard_audit_logger);
        g_guard_audit_logger = NULL;
    }
    if (g_guard_manager) {
        guard_manager_destroy(g_guard_manager);
        g_guard_manager = NULL;
    }
    __builtin_memset(g_current_agent_id, 0, sizeof(g_current_agent_id));
    AIRY_STRNCPY_TERM(g_current_agent_id, "system", sizeof(g_current_agent_id));
    g_guards_enabled = false;
}

/**
 * @brief Set the current agent ID (for external callers to set the real
 *        agent identity)
 * @param agent_id Agent identifier
 */
CUPOLAS_API void cupolas_guards_set_agent_id(const char *agent_id)
{
    if (!agent_id)
        return;
    AIRY_STRNCPY_TERM(g_current_agent_id, agent_id, sizeof(g_current_agent_id));
}

/**
 * @brief Enable guards
 */
CUPOLAS_API void cupolas_guards_enable(void)
{
    g_guards_enabled = true;
}

/**
 * @brief Disable guards
 */
CUPOLAS_API void cupolas_guards_disable(void)
{
    g_guards_enabled = false;
}

/**
 * @brief Check whether guards are enabled
 * @return 1 if enabled, 0 if disabled
 */
CUPOLAS_API int cupolas_guards_is_enabled(void)
{
    return g_guards_enabled ? 1 : 0;
}

/**
 * @brief Get the guard manager instance
 * @return Guard manager handle
 */
CUPOLAS_API guard_manager_t *cupolas_guards_get_manager(void)
{
    return g_guard_manager;
}

/**
 * @brief Register a guard with Cupolas
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int cupolas_guards_register_guard(guard_t *guard)
{
    if (!g_guard_manager) {
        return cupolas_ERROR_BUSY;
    }

    return guard_manager_register_guard(g_guard_manager, guard);
}

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
                                     size_t *actual_results)
{
    if (!g_guard_manager || !g_guards_enabled) {
        if (actual_results)
            *actual_results = 0;
        return cupolas_ERROR_BUSY;
    }

    guard_context_t guard_ctx = {.operation = operation,
                                 .resource = resource,
                                 .agent_id = agent_id,
                                 .session_id = NULL,
                                 .input_data = (void *)input_data,
                                 .input_size = input_size,
                                 .context_data = NULL,
                                 .timestamp = cupolas_get_timestamp_ns()};

    return guard_manager_check_sync(g_guard_manager, &guard_ctx, results, max_results,
                                    actual_results);
}
