// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file guard_integration.c
 * @brief SafetyGuard integration with Cupolas components.
 *
 * Integrates the SafetyGuard framework into existing Cupolas components:
 * 1. Post-permission-check guard
 * 2. Pre-command-execution guard
 * 3. Input sanitization guard
 * 4. Enhanced audit logging
 */

#include "../../include/cupolas.h"
#include "../audit/audit.h"
#include "../permission/permission.h"
#include "../sanitizer/sanitizer.h"
#include "../utils/cupolas_utils.h"
#include "../workbench/workbench.h"
#include "guard_core.h"
#include "logging.h"
#include "platform.h"
#include "airy_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// ============================================================================

static guard_manager_t *g_guard_manager = NULL;
static bool g_guards_enabled = false;
static audit_logger_t *g_guard_audit_logger = NULL;
static char g_current_agent_id[64] = "system";

/**
 * @brief Record a security guard audit log
 */
static void guard_log_security(const char *agent_id, const char *action, const char *resource,
                               int risk_level, const char *detail)
{
    if (!g_guard_audit_logger)
        return;
    char buf[256];
    snprintf(buf, sizeof(buf), "risk_level=%d %s", risk_level, detail ? detail : "");
    audit_logger_log(g_guard_audit_logger, AUDIT_EVENT_PERMISSION, agent_id, action, resource, buf,
                     0);
}

// ============================================================================
// ============================================================================

/**
 * @brief Permission-check guard hook
 * @note [SECURITY] Reserved for future permission enhancements
 */
static int __attribute__((unused)) permission_guard_hook(const char *agent_id, const char *action,
                                                         const char *resource, const char *context,
                                                         int permission_result)
{
    if (!g_guard_manager || !g_guards_enabled) {
        return permission_result;
    }

    if (permission_result != 1) {
        return permission_result;
    }

    guard_context_t guard_ctx = {.operation = "permission_check",
                                 .resource = resource,
                                 .agent_id = agent_id,
                                 .session_id = context,
                                 .input_data = (void *)action,
                                 .input_size = action ? strlen(action) + 1 : 0,
                                 .context_data = NULL,
                                 .timestamp = cupolas_get_timestamp_ns()};

#define MAX_RESULTS 8
    guard_result_t results[MAX_RESULTS];
    size_t actual_results = 0;

    int guard_result = guard_manager_check_sync(g_guard_manager, &guard_ctx, results, MAX_RESULTS,
                                                &actual_results);

    if (guard_result != CUPOLAS_OK) {
        return permission_result;
    }

    for (size_t i = 0; i < actual_results; i++) {
        guard_result_t *result = &results[i];

        switch (result->risk_level) {
        case RISK_LEVEL_SAFE:
        case RISK_LEVEL_INFO:
            break;

        case RISK_LEVEL_LOW:
            guard_log_security(agent_id, action, resource, RISK_LEVEL_LOW, "low_risk_allowed");
            break;

        case RISK_LEVEL_MEDIUM:
        case RISK_LEVEL_HIGH:
        case RISK_LEVEL_CRITICAL:
            if (result->recommended_action == GUARD_ACTION_BLOCK ||
                result->recommended_action == GUARD_ACTION_ISOLATE ||
                result->recommended_action == GUARD_ACTION_TERMINATE) {
                guard_log_security(agent_id, action, resource, result->risk_level,
                                   "blocked_by_guard");
                return 0;
            }
            break;

        default:
            break;
        }
    }

    return permission_result;
}

/**
 * @brief Command-execution guard hook
 * @note [SECURITY] Reserved for future command security enhancements
 */
static int __attribute__((unused)) command_execution_guard_hook(const char *command,
                                                                char *const argv[])
{
    if (!g_guard_manager || !g_guards_enabled) {
        return CUPOLAS_OK;
    }

    char cmd_buffer[1024] = {0};
    size_t pos = 0;

    if (command) {
        pos += snprintf(cmd_buffer + pos, sizeof(cmd_buffer) - pos, "%s", command);
    }

    if (argv) {
        for (int i = 0; argv[i] && pos < sizeof(cmd_buffer) - 1; i++) {
            pos += snprintf(cmd_buffer + pos, sizeof(cmd_buffer) - pos, " %s", argv[i]);
        }
    }

    guard_context_t guard_ctx = {.operation = "command_execution",
                                 .resource = "workbench",
                                 .agent_id = g_current_agent_id,
                                 .session_id = NULL,
                                 .input_data = cmd_buffer,
                                 .input_size = strlen(cmd_buffer) + 1,
                                 .context_data = NULL,
                                 .timestamp = cupolas_get_timestamp_ns()};

#define MAX_RESULTS 8
    guard_result_t results[MAX_RESULTS];
    size_t actual_results = 0;

    int guard_result = guard_manager_check_sync(g_guard_manager, &guard_ctx, results, MAX_RESULTS,
                                                &actual_results);

    if (guard_result != CUPOLAS_OK) {
        return CUPOLAS_OK;
    }

    for (size_t i = 0; i < actual_results; i++) {
        guard_result_t *result = &results[i];

        switch (result->risk_level) {
        case RISK_LEVEL_SAFE:
        case RISK_LEVEL_INFO:
            break;

        case RISK_LEVEL_LOW:
            guard_log_security("system", command, "command_execute", RISK_LEVEL_LOW,
                               "low_risk_cmd_allowed");
            break;

        case RISK_LEVEL_MEDIUM:
        case RISK_LEVEL_HIGH:
        case RISK_LEVEL_CRITICAL:
            if (result->recommended_action == GUARD_ACTION_BLOCK ||
                result->recommended_action == GUARD_ACTION_ISOLATE ||
                result->recommended_action == GUARD_ACTION_TERMINATE) {
                guard_log_security("system", command, "command_execute", result->risk_level,
                                   "cmd_blocked_by_guard");
                return cupolas_ERROR_PERMISSION;
            }
            break;

        default:
            break;
        }
    }

    return CUPOLAS_OK;
}

/**
 * @brief Input sanitization guard hook
 * @note [SECURITY] Reserved for future input sanitization enhancements
 */
static int __attribute__((unused)) sanitizer_guard_hook(const char *input, char *output,
                                                        size_t output_size, int sanitizer_result)
{
    (void)input;
    if (!g_guard_manager || !g_guards_enabled) {
        return sanitizer_result;
    }

    if (sanitizer_result != CUPOLAS_OK || !output) {
        return sanitizer_result;
    }

    guard_context_t guard_ctx = {.operation = "input_sanitization",
                                 .resource = "sanitizer",
                                 .agent_id = g_current_agent_id,
                                 .session_id = NULL,
                                 .input_data = (void *)output,
                                 .input_size = strlen(output) + 1,
                                 .context_data = NULL,
                                 .timestamp = cupolas_get_timestamp_ns()};

#define MAX_RESULTS 8
    guard_result_t results[MAX_RESULTS];
    size_t actual_results = 0;

    int guard_result = guard_manager_check_sync(g_guard_manager, &guard_ctx, results, MAX_RESULTS,
                                                &actual_results);

    if (guard_result != CUPOLAS_OK) {
        return sanitizer_result;
    }

    for (size_t i = 0; i < actual_results; i++) {
        guard_result_t *result = &results[i];

        if (result->risk_level >= RISK_LEVEL_MEDIUM) {
            guard_log_security("system", "sanitize_input", "input_data", result->risk_level,
                               "high_risk_input_detected");

            if (result->risk_level == RISK_LEVEL_CRITICAL) {
                if (output_size > 0)
                    output[0] = '\0';
                return cupolas_ERROR_INVALID_ARG;
            }
        }
    }

    return sanitizer_result;
}

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

// ============================================================================
// ============================================================================

/**
 * @brief Register the Cupolas hooks
 *
 * Registers the guard hooks into the Cupolas components.
 * Note: must be called after Cupolas initialization.
 */
CUPOLAS_API int cupolas_guards_register_hooks(void)
{
    if (!g_guard_manager) {
        return cupolas_ERROR_BUSY;
    }

    static int hooks_registered = 0;
    if (hooks_registered) {
        return CUPOLAS_OK;
    }

    AIRY_LOG_INFO("[GUARD] Registering safety hooks to Cupolas components...");

    int registered_count = 0;

#ifdef CUPOLAS_HAS_PERMISSION_HOOK
    if (permission_register_post_check_hook(permission_guard_hook) == 0) {
        registered_count++;
        AIRY_LOG_INFO("[GUARD] Permission post-check hook registered");
    } else {
        AIRY_LOG_ERROR("[GUARD] Failed to register permission hook");
    }
#endif

#ifdef CUPOLAS_HAS_WORKBENCH_HOOK
    if (workbench_register_pre_exec_hook(command_execution_guard_hook) == 0) {
        registered_count++;
        AIRY_LOG_INFO("[GUARD] Workbench pre-execution hook registered");
    } else {
        AIRY_LOG_ERROR("[GUARD] Failed to register workbench hook");
    }
#endif

#ifdef CUPOLAS_HAS_SANITIZER_HOOK
    if (sanitizer_register_post_process_hook(sanitizer_guard_hook) == 0) {
        registered_count++;
        AIRY_LOG_INFO("[GUARD] Sanitizer post-process hook registered");
    } else {
        AIRY_LOG_ERROR("[GUARD] Failed to register sanitizer hook");
    }
#endif

    if (registered_count > 0) {
        hooks_registered = 1;
        g_guards_enabled = true;
        AIRY_LOG_INFO("[GUARD] Successfully registered %d safety hooks", registered_count);
        return CUPOLAS_OK;
    }

    AIRY_LOG_WARN("[GUARD] Warning: No hooks registered (component hook APIs not available)");
    AIRY_LOG_INFO("[GUARD] Guards will work in standalone mode (explicit checks only)");
    return CUPOLAS_OK;
}

/**
 * @brief Unregister the Cupolas hooks
 */
CUPOLAS_API void cupolas_guards_unregister_hooks(void)
{
    AIRY_LOG_INFO("[GUARD] Unregistering safety hooks from Cupolas components...");

#ifdef CUPOLAS_HAS_PERMISSION_HOOK
    permission_unregister_post_check_hook();
    AIRY_LOG_INFO("[GUARD] Permission hook unregistered");
#endif

#ifdef CUPOLAS_HAS_WORKBENCH_HOOK
    workbench_unregister_pre_exec_hook();
    AIRY_LOG_INFO("[GUARD] Workbench hook unregistered");
#endif

#ifdef CUPOLAS_HAS_SANITIZER_HOOK
    sanitizer_unregister_post_process_hook();
    AIRY_LOG_INFO("[GUARD] Sanitizer hook unregistered");
#endif

    g_guards_enabled = false;
    AIRY_LOG_INFO("[GUARD] All safety hooks unregistered");
}
