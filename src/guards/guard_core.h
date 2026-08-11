/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file guard_core.h
 * @brief SafetyGuard Core Framework
 *
 * 安全守卫框架核心定义，提供统一的安全检测接口和守卫管理器。
 * 支持多种守卫类型（规则、模型、行为分析等）和优先级调度。
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
 * @brief 创建守卫管理器
 * @param config 管理器配置
 * @return 守卫管理器句柄，失败返回NULL
 */
CUPOLAS_API guard_manager_t *guard_manager_create(const guard_manager_config_t *config);

/**
 * @brief 销毁守卫管理器
 * @param manager 守卫管理器句柄
 */
CUPOLAS_API void guard_manager_destroy(guard_manager_t *manager);

/**
 * @brief 注册守卫到管理器
 * @param manager 守卫管理器
 * @param guard 守卫实例
 * @return 错误码
 */
CUPOLAS_API int guard_manager_register_guard(guard_manager_t *manager, guard_t *guard);

/**
 * @brief 从管理器注销守卫
 * @param manager 守卫管理器
 * @param guard_id 守卫ID
 * @return 错误码
 */
CUPOLAS_API int guard_manager_unregister_guard(guard_manager_t *manager, guard_id_t guard_id);

/**
 * @brief 根据名称查找守卫
 * @param manager 守卫管理器
 * @param name 守卫名称
 * @return 守卫实例，未找到返回NULL
 */
CUPOLAS_API guard_t *guard_manager_find_guard_by_name(guard_manager_t *manager, const char *name);

/**
 * @brief 根据ID查找守卫
 * @param manager 守卫管理器
 * @param id 守卫ID
 * @return 守卫实例，未找到返回NULL
 */
CUPOLAS_API guard_t *guard_manager_find_guard_by_id(guard_manager_t *manager, guard_id_t id);

/**
 * @brief 执行安全检测（同步）
 * @param manager 守卫管理器
 * @param context 检测上下文
 * @param results 结果数组（输出）
 * @param max_results 最大结果数
 * @param actual_results 实际结果数（输出）
 * @return 错误码
 */
CUPOLAS_API int guard_manager_check_sync(guard_manager_t *manager, const guard_context_t *context,
                                         guard_result_t *results, size_t max_results,
                                         size_t *actual_results);

/**
 * @brief 执行安全检测（异步）
 * @param manager 守卫管理器
 * @param context 检测上下文
 * @param callback 回调函数
 * @param user_data 用户数据
 * @return 请求ID，失败返回0
 */
CUPOLAS_API uint64_t guard_manager_check_async(guard_manager_t *manager,
                                               const guard_context_t *context,
                                               void (*callback)(uint64_t request_id,
                                                                const guard_result_t *results,
                                                                size_t count, void *user_data),
                                               void *user_data);

/**
 * @brief 获取管理器统计信息
 * @param manager 守卫管理器
 * @param stats 统计信息（输出）
 * @return 错误码
 */
CUPOLAS_API int guard_manager_get_stats(guard_manager_t *manager, guard_stats_t *stats);

/**
 * @brief 重置管理器统计信息
 * @param manager 守卫管理器
 * @return 错误码
 */
CUPOLAS_API int guard_manager_reset_stats(guard_manager_t *manager);

/* ============================================================================ */

/* ============================================================================ */
/**
 * @brief 创建守卫实例
 * @param name 守卫名称
 * @param description 守卫描述
 * @param type 守卫类型
 * @param ops 守卫操作函数表
 * @return 守卫实例，失败返回NULL
 */
CUPOLAS_API guard_t *guard_create(const char *name, const char *description, guard_type_t type,
                                  const guard_ops_t *ops);

/**
 * @brief 销毁守卫实例
 * @param guard 守卫实例
 */
CUPOLAS_API void guard_destroy(guard_t *guard);

/**
 * @brief 初始化守卫
 * @param guard 守卫实例
 * @param config 守卫配置
 * @return 错误码
 */
CUPOLAS_API int guard_init(guard_t *guard, const guard_config_t *config);

/**
 * @brief 执行守卫检测
 * @param guard 守卫实例
 * @param context 检测上下文
 * @param result 检测结果（输出）
 * @return 错误码
 */
CUPOLAS_API int guard_check(guard_t *guard, const guard_context_t *context, guard_result_t *result);

/**
 * @brief 启用守卫
 * @param guard 守卫实例
 * @return 错误码
 */
CUPOLAS_API int guard_enable(guard_t *guard);

/**
 * @brief 禁用守卫
 * @param guard 守卫实例
 * @return 错误码
 */
CUPOLAS_API int guard_disable(guard_t *guard);

/**
 * @brief 更新守卫规则
 * @param guard 守卫实例
 * @param rules 规则数组
 * @param count 规则数量
 * @return 错误码
 */
CUPOLAS_API int guard_update_rules(guard_t *guard, const guard_rule_t *rules, size_t count);

/**
 * @brief 获取守卫统计信息
 * @param guard 守卫实例
 * @param stats 统计信息（输出）
 * @return 错误码
 */
CUPOLAS_API int guard_get_stats(guard_t *guard, guard_stats_t *stats);

/**
 * @brief 重置守卫统计信息
 * @param guard 守卫实例
 * @return 错误码
 */
CUPOLAS_API int guard_reset_stats(guard_t *guard);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_GUARD_CORE_H */