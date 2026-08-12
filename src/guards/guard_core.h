/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file guard_core.h
 * @brief SafetyGuard core framework.
 *
 * Core definitions of the safety guard framework: a unified security
 * check interface and a guard manager supporting multiple guard types
 * (rule, model, behavioral, etc.) and priority scheduling.
 */

#ifndef CUPOLAS_GUARD_CORE_H
#define CUPOLAS_GUARD_CORE_H

#include "../../include/cupolas.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */

/* ============================================================================ */

#define GUARD_NAME_MAX_LEN 64


#define GUARD_DESC_MAX_LEN 256


#define GUARD_MAX_RULES 1024


typedef uint64_t guard_id_t;


typedef enum {
    GUARD_TYPE_RULE_BASED = 0,
    GUARD_TYPE_MODEL_BASED,
    GUARD_TYPE_BEHAVIORAL,
    GUARD_TYPE_HEURISTIC,
    GUARD_TYPE_EXTERNAL,
    GUARD_TYPE_COMPOSITE,
    GUARD_TYPE_CUSTOM
} guard_type_t;


typedef enum {
    RISK_LEVEL_SAFE = 0,
    RISK_LEVEL_INFO,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_MAX
} risk_level_t;


typedef enum {
    GUARD_ACTION_ALLOW = 0,
    GUARD_ACTION_WARN,
    GUARD_ACTION_BLOCK,
    GUARD_ACTION_ISOLATE,
    GUARD_ACTION_TERMINATE,
    GUARD_ACTION_ESCALATE
} guard_action_t;


typedef enum {
    GUARD_PRIORITY_LOWEST = 0,
    GUARD_PRIORITY_LOW,
    GUARD_PRIORITY_NORMAL,
    GUARD_PRIORITY_HIGH,
    GUARD_PRIORITY_HIGHEST,
    GUARD_PRIORITY_CRITICAL
} guard_priority_t;


typedef enum {
    GUARD_STATE_DISABLED = 0,
    GUARD_STATE_ENABLED,
    GUARD_STATE_ACTIVE,
    GUARD_STATE_ERROR,
    GUARD_STATE_UPDATING
} guard_state_t;

/* ============================================================================ */

/* ============================================================================ */

typedef struct {
    const char *operation;
    const char *resource;
    const char *agent_id;
    const char *session_id;
    void *input_data;
    size_t input_size;
    void *context_data;
    uint64_t timestamp;
} guard_context_t;


typedef struct {
    risk_level_t risk_level;
    guard_action_t recommended_action;
    const char *risk_type;
    const char *description;
    float confidence;
    void *evidence;
    size_t evidence_size;
    uint64_t detection_time;
} guard_result_t;


typedef struct {
    const char *rule_id;
    const char *pattern;
    risk_level_t risk_level;
    guard_action_t action;
    bool case_sensitive;
    void *user_data;
} guard_rule_t;


typedef struct {
    guard_type_t guard_type;
    guard_priority_t priority;
    size_t max_rules;
    bool enable_logging;
    bool enable_metrics;
    size_t cache_size;
    uint32_t timeout_ms;
    void *custom_config;
    size_t custom_config_size;
} guard_config_t;


typedef struct {
    uint64_t total_checks;
    uint64_t safe_checks;
    uint64_t risky_checks;
    uint64_t blocked_operations;
    uint64_t warning_operations;
    uint64_t false_positives;
    uint64_t false_negatives;
    uint64_t error_checks;
    uint64_t timeout_checks;
    uint64_t total_detection_time;
    uint64_t max_detection_time;
} guard_stats_t;


typedef struct guard_ops {

    int (*init)(void *guard, const guard_config_t *config);


    void (*cleanup)(void *guard);


    int (*check)(void *guard, const guard_context_t *context, guard_result_t *result);


    int (*update_rules)(void *guard, const guard_rule_t *rules, size_t count);


    int (*get_stats)(void *guard, guard_stats_t *stats);


    int (*reset_stats)(void *guard);


    int (*self_test)(void *guard);
} guard_ops_t;


typedef struct guard {
    guard_id_t id;
    char name[GUARD_NAME_MAX_LEN];
    char description[GUARD_DESC_MAX_LEN];
    guard_type_t type;
    guard_priority_t priority;
    guard_state_t state;
    guard_config_t config;
    guard_ops_t *ops;
    void *priv_data;
    guard_stats_t stats;
    uint64_t created_time;
    uint64_t last_used_time;
} guard_t;


typedef struct {
    size_t max_guards;
    size_t max_pending_checks;
    bool enable_priority_scheduling;
    bool enable_result_caching;
    size_t cache_ttl_seconds;
    uint32_t default_timeout_ms;
} guard_manager_config_t;


typedef struct guard_manager guard_manager_t;

/* ============================================================================ */

/* ============================================================================ */
/**
 * @brief Create a guard manager
 * @param config Manager configuration
 * @return Guard manager handle, NULL on failure
 */
CUPOLAS_API guard_manager_t *guard_manager_create(const guard_manager_config_t *config);

/**
 * @brief Destroy a guard manager
 * @param manager Guard manager handle
 */
CUPOLAS_API void guard_manager_destroy(guard_manager_t *manager);

/**
 * @brief Register a guard with the manager
 * @param manager Guard manager
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int guard_manager_register_guard(guard_manager_t *manager, guard_t *guard);

/**
 * @brief Unregister a guard from the manager
 * @param manager Guard manager
 * @param guard_id Guard ID
 * @return Error code
 */
CUPOLAS_API int guard_manager_unregister_guard(guard_manager_t *manager, guard_id_t guard_id);

/**
 * @brief Find a guard by name
 * @param manager Guard manager
 * @param name Guard name
 * @return Guard instance, NULL if not found
 */
CUPOLAS_API guard_t *guard_manager_find_guard_by_name(guard_manager_t *manager, const char *name);

/**
 * @brief Find a guard by ID
 * @param manager Guard manager
 * @param id Guard ID
 * @return Guard instance, NULL if not found
 */
CUPOLAS_API guard_t *guard_manager_find_guard_by_id(guard_manager_t *manager, guard_id_t id);

/**
 * @brief Run security checks (synchronous)
 * @param manager Guard manager
 * @param context Check context
 * @param results Result array (output)
 * @param max_results Maximum number of results
 * @param actual_results Actual number of results (output)
 * @return Error code
 */
CUPOLAS_API int guard_manager_check_sync(guard_manager_t *manager, const guard_context_t *context,
                                         guard_result_t *results, size_t max_results,
                                         size_t *actual_results);

/**
 * @brief Run security checks (asynchronous)
 * @param manager Guard manager
 * @param context Check context
 * @param callback Completion callback
 * @param user_data Callback user data
 * @return Request ID, 0 on failure
 */
CUPOLAS_API uint64_t guard_manager_check_async(guard_manager_t *manager,
                                               const guard_context_t *context,
                                               void (*callback)(uint64_t request_id,
                                                                const guard_result_t *results,
                                                                size_t count, void *user_data),
                                               void *user_data);

/**
 * @brief Get manager statistics
 * @param manager Guard manager
 * @param stats Statistics (output)
 * @return Error code
 */
CUPOLAS_API int guard_manager_get_stats(guard_manager_t *manager, guard_stats_t *stats);

/**
 * @brief Reset manager statistics
 * @param manager Guard manager
 * @return Error code
 */
CUPOLAS_API int guard_manager_reset_stats(guard_manager_t *manager);

/* ============================================================================ */

/* ============================================================================ */
/**
 * @brief Create a guard instance
 * @param name Guard name
 * @param description Guard description
 * @param type Guard type
 * @param ops Guard operation function table
 * @return Guard instance, NULL on failure
 */
CUPOLAS_API guard_t *guard_create(const char *name, const char *description, guard_type_t type,
                                  const guard_ops_t *ops);

/**
 * @brief Destroy a guard instance
 * @param guard Guard instance
 */
CUPOLAS_API void guard_destroy(guard_t *guard);

/**
 * @brief Initialize a guard
 * @param guard Guard instance
 * @param config Guard configuration
 * @return Error code
 */
CUPOLAS_API int guard_init(guard_t *guard, const guard_config_t *config);

/**
 * @brief Run a guard check
 * @param guard Guard instance
 * @param context Check context
 * @param result Check result (output)
 * @return Error code
 */
CUPOLAS_API int guard_check(guard_t *guard, const guard_context_t *context, guard_result_t *result);

/**
 * @brief Enable a guard
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int guard_enable(guard_t *guard);

/**
 * @brief Disable a guard
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int guard_disable(guard_t *guard);

/**
 * @brief Update guard rules
 * @param guard Guard instance
 * @param rules Rule array
 * @param count Number of rules
 * @return Error code
 */
CUPOLAS_API int guard_update_rules(guard_t *guard, const guard_rule_t *rules, size_t count);

/**
 * @brief Get guard statistics
 * @param guard Guard instance
 * @param stats Statistics (output)
 * @return Error code
 */
CUPOLAS_API int guard_get_stats(guard_t *guard, guard_stats_t *stats);

/**
 * @brief Reset guard statistics
 * @param guard Guard instance
 * @return Error code
 */
CUPOLAS_API int guard_reset_stats(guard_t *guard);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_GUARD_CORE_H */