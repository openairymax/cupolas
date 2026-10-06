// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas.c - AgentRT Security Dome Core Implementation (Facade)
 *
 * This module implements the unified public API for the security dome,
 * providing a facade over all four protection layers:
 * - Virtual Workbench (workbench/)
 * - Permission Engine (permission/)
 * - Input Sanitizer (sanitizer/)
 * - Audit Trail (audit/)
 */

#include "platform_misc.h"
#include "atomic_compat.h"
#include "cupolas.h"

#include "audit/audit.h"
#include "error.h"
#include "guards/guard_integration.h"
#include "permission/permission.h"
#include "platform.h"
#include "sanitizer/sanitizer.h"
#include "security/cupolas_error.h"
#include "utils/cupolas_utils.h"
#include "airy_memory.h"
#include "airyrt_version.h"
#include "workbench/workbench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CUPOLAS_DEFAULT_AUDIT_MAX_FILE_SIZE (10 * 1024 * 1024)
#define CUPOLAS_DEFAULT_AUDIT_MAX_FILES 5
#define CUPOLAS_CONFIG_PATH_MAX 512
#define CUPOLAS_GUARD_MAX_RESULTS 8

typedef struct {
    char permission_rules_path[CUPOLAS_CONFIG_PATH_MAX];
    char audit_log_dir[CUPOLAS_CONFIG_PATH_MAX];
} cupolas_internal_config_t;

static void cupolas_internal_config_init_defaults(cupolas_internal_config_t *cfg)
{
    if (!cfg)
        return;
    __builtin_memset(cfg, 0, sizeof(*cfg));
    /* 默认路径必须走运行期 AIRY_HOME 路径系统
     * （airy_config_dir()/airy_log_dir()，由 airy_paths_init() 依
     * $AIRY_HOME 解析并导出 $AIRY_CONFIG_DIR/$AIRY_LOG_DIR），而非
     * 编译期宏 AIRY_CONFIG_DIR/AIRY_LOG_DIR（= /etc/agentrt、
     * /var/log/agentrt）。若按编译期路径加载 permission_rules.yaml，
     * 部署到 $AIRY_HOME 下时该文件不存在 → 规则为空 → fail-closed
     * 拒绝所有工具。 */
#ifdef _WIN32
    snprintf(cfg->permission_rules_path, sizeof(cfg->permission_rules_path),
             "%s\\cupolas\\permission_rules.yaml", airy_config_dir());
    snprintf(cfg->audit_log_dir, sizeof(cfg->audit_log_dir), "%s\\cupolas", airy_log_dir());
#else
    snprintf(cfg->permission_rules_path, sizeof(cfg->permission_rules_path),
             "%s/cupolas/permission_rules.yaml", airy_config_dir());
    snprintf(cfg->audit_log_dir, sizeof(cfg->audit_log_dir), "%s/cupolas", airy_log_dir());
#endif
}

static void cupolas_internal_config_cleanup(cupolas_internal_config_t *cfg)
{
    if (!cfg)
        return;
    cupolas_memset_s(cfg, sizeof(*cfg));
}

static struct {
    int initialized;
    cupolas_internal_config_t config;
    permission_engine_t *perm;
    sanitizer_t *san;
    workbench_t *wb;
    audit_logger_t *audit;
    airy_mtx_t lock;
} g_cupolas = {0};

/* N3 fix: DCLP guards the concurrent cupolas_init() entry.
 * State machine: 0 = uninitialized, 2 = initializing, 1 = ready.
 * CAS ensures only one thread runs the initialization; the others spin
 * until the state becomes 1. Follows the DCLP pattern of core_init.c. */
static atomic_int g_cupolas_init_state = 0;

#define CUPOLAS_INIT_SPIN_MAX_RETRIES 10000000UL

/* init 失败回收机制件：按依赖逆序幂等回收已建组件，NULL 字段跳过。 */
static void cupolas_init_reclaim(void)
{
    if (g_cupolas.audit) {
        audit_logger_destroy(g_cupolas.audit);
        g_cupolas.audit = NULL;
    }
    if (g_cupolas.san) {
        sanitizer_destroy(g_cupolas.san);
        g_cupolas.san = NULL;
    }
    if (g_cupolas.perm) {
        permission_engine_destroy(g_cupolas.perm);
        g_cupolas.perm = NULL;
    }
}

/* calloc 失败统一收尾机制件：OOM 出参、幂等回收、解锁销锁、复位初始化状态。 */
static int cupolas_init_fail(const char *what, airy_err_t *error)
{
    if (error)
        *error = AIRY_ERR_OUT_OF_MEMORY;
    cupolas_init_reclaim();

    airy_mtx_unlock(&g_cupolas.lock);
    airy_mtx_destroy(&g_cupolas.lock);

    atomic_store_32(&g_cupolas_init_state, 0, memory_order_seq_cst);
    CUPOLAS_LOG_ERROR("cupolas_init: %s failed", what);
    return cupolas_ERR_OUT_OF_MEMORY;
}

static int cupolas_init_ex(const char *config_path, airy_err_t *error, int with_perm)
{
    CUPOLAS_LOG_INFO("cupolas_init%s: initializing security dome (config=%s)",
                     with_perm ? "" : "_pep", config_path ? config_path : "default");

    if (atomic_load_32(&g_cupolas_init_state, memory_order_seq_cst) == 1) {
        return CUPOLAS_OK;
    }

    int expected = 0;
    if (!atomic_compare_exchange_strong_32(&g_cupolas_init_state, &expected, 2,
                                           memory_order_seq_cst,
                                           memory_order_seq_cst)) {

        if (atomic_load_32(&g_cupolas_init_state, memory_order_seq_cst) == 1) {
            return CUPOLAS_OK;
        }

        unsigned long spin_count = 0;
        while (atomic_load_32(&g_cupolas_init_state, memory_order_seq_cst) == 2) {
            airy_sleep_us(1);
            if (++spin_count >= CUPOLAS_INIT_SPIN_MAX_RETRIES) {
                /* V4.0-S3 fix: on timeout do not CAS-reset 2->0, only fail.
                 * The V3.0-N2 CAS 2->0 reset raced: after a timed-out thread
                 * reset state=0, a third thread could CAS 0->2 and start a
                 * second initialization. Keeping state=2 prevents new threads
                 * from entering the init path; the final state is decided by
                 * the initializing thread (store 1 on success, 0 on failure). */
                if (error)
                    *error = AIRY_ERR_TIMEOUT;
                CUPOLAS_LOG_ERROR("cupolas_init: init spin-wait timed out after %lu retries",
                                  spin_count);
                return cupolas_ERR_STATE_ERROR;
            }
        }
        /* V3.0-N1 fix: after spinning out, verify state == 1. If state == 0
         * the initializing thread failed (stored 0 on the error path); the
         * waiter must not return CUPOLAS_OK, or the caller would operate on
         * an uninitialized security dome. */
        if (atomic_load_32(&g_cupolas_init_state, memory_order_seq_cst) != 1) {
            if (error)
                *error = AIRY_ERR_SYS_NOT_INIT;
            CUPOLAS_LOG_ERROR("cupolas_init: initialization failed by other thread (state=0)");
            return cupolas_ERR_STATE_ERROR;
        }
        return CUPOLAS_OK;
    }

    __builtin_memset(&g_cupolas, 0, sizeof(g_cupolas));

    if (airy_mtx_init(&g_cupolas.lock) != 0) {
        if (error)
            *error = AIRY_ERR_IO;
        CUPOLAS_LOG_ERROR("cupolas_init: mutex init failed");

        atomic_store_32(&g_cupolas_init_state, 0, memory_order_seq_cst);
        return cupolas_ERR_UNKNOWN;
    }

    airy_mtx_lock(&g_cupolas.lock);

    cupolas_internal_config_init_defaults(&g_cupolas.config);

    /* pep 模式不构造本地 permission 引擎——策略
     * 唯一持有者为 PDP（cupolas_d）；本地仅保留 sanitizer/workbench/audit。 */
    if (with_perm) {
        g_cupolas.perm = permission_engine_create(
            g_cupolas.config.permission_rules_path[0] ? g_cupolas.config.permission_rules_path :
                                                        NULL);
        if (!g_cupolas.perm) {
            return cupolas_init_fail("calloc permission engine", error);
        }
    }

    g_cupolas.san = sanitizer_create(NULL);
    if (!g_cupolas.san) {
        return cupolas_init_fail("calloc sanitizer", error);
    }

    g_cupolas.wb = NULL;

    g_cupolas.audit =
        audit_logger_create(g_cupolas.config.audit_log_dir[0] ? g_cupolas.config.audit_log_dir :
                                                                ".",
                            "cupolas_audit", CUPOLAS_DEFAULT_AUDIT_MAX_FILE_SIZE,
                            CUPOLAS_DEFAULT_AUDIT_MAX_FILES);
    if (!g_cupolas.audit) {
        return cupolas_init_fail("calloc audit_logger", error);
    }

    g_cupolas.initialized = 1;
    airy_mtx_unlock(&g_cupolas.lock);

    /* N3 fix: publish the ready state (2->1) to wake up spinning threads.
     * Must happen after unlock so waiters observe initialized=1 and state=1
     * consistently. */
    atomic_store_32(&g_cupolas_init_state, 1, memory_order_seq_cst);

    if (with_perm)
        CUPOLAS_LOG_INFO(
            "cupolas_init: security dome ready (permission+sanitizer+workbench+audit)");
    else
        CUPOLAS_LOG_INFO(
            "cupolas_init_pep: security dome ready (sanitizer+workbench+audit; "
            "permission owned by PDP)");
    return CUPOLAS_OK;
}

int cupolas_init(const char *config_path, airy_err_t *error)
{
    return cupolas_init_ex(config_path, error, 1);
}

int cupolas_init_pep(const char *config_path, airy_err_t *error)
{
    return cupolas_init_ex(config_path, error, 0);
}

void cupolas_cleanup(void)
{
    if (!g_cupolas.initialized) {
        return;
    }

    CUPOLAS_LOG_INFO("cupolas_cleanup: shutting down security dome...");
    airy_mtx_lock(&g_cupolas.lock);

    if (g_cupolas.audit) {
        audit_logger_flush(g_cupolas.audit);
        audit_logger_destroy(g_cupolas.audit);
        g_cupolas.audit = NULL;
        CUPOLAS_LOG_INFO("cupolas_cleanup: [OK] audit logger destroyed");
    }

    if (g_cupolas.wb) {
        workbench_destroy(g_cupolas.wb);
        g_cupolas.wb = NULL;
        CUPOLAS_LOG_INFO("cupolas_cleanup: [OK] workbench destroyed");
    }

    if (g_cupolas.san) {
        sanitizer_destroy(g_cupolas.san);
        g_cupolas.san = NULL;
        CUPOLAS_LOG_INFO("cupolas_cleanup: [OK] sanitizer destroyed");
    }

    if (g_cupolas.perm) {
        if (g_cupolas.perm) {
            permission_engine_destroy(g_cupolas.perm);
            g_cupolas.perm = NULL;
        }
        CUPOLAS_LOG_INFO("cupolas_cleanup: [OK] permission engine destroyed");
    }

    cupolas_internal_config_cleanup(&g_cupolas.config);

    g_cupolas.initialized = 0;
    airy_mtx_unlock(&g_cupolas.lock);

    airy_mtx_destroy(&g_cupolas.lock);

    atomic_store_32(&g_cupolas_init_state, 0, memory_order_seq_cst);
    CUPOLAS_LOG_INFO("cupolas_cleanup: security dome shutdown complete");
}

const char *cupolas_version(void)
{
    return AIRYRT_VERSION;
}

/* guard 同步审查机制件：管理器就绪检查、同步检查与中风险阻断判定为机制；
 * 审计落账与拦截返回路径为策略，由调用方持有。命中阻断返回 true。 */
static bool guards_blocking(const guard_context_t *ctx)
{
    guard_manager_t *gm = cupolas_guards_is_enabled() ? cupolas_guards_get_manager() : NULL;
    if (!gm) {
        return false;
    }

    guard_result_t results[CUPOLAS_GUARD_MAX_RESULTS];
    size_t actual = 0;
    if (guard_manager_check_sync(gm, ctx, results, CUPOLAS_GUARD_MAX_RESULTS, &actual) != 0) {
        return false;
    }

    for (size_t i = 0; i < actual; i++) {
        const guard_result_t *gr = &results[i];
        if (gr->risk_level >= RISK_LEVEL_MEDIUM &&
            (gr->recommended_action == GUARD_ACTION_BLOCK ||
             gr->recommended_action == GUARD_ACTION_ISOLATE ||
             gr->recommended_action == GUARD_ACTION_TERMINATE)) {
            return true;
        }
    }
    return false;
}

int cupolas_check_permission(const char *agent_id, const char *action, const char *resource,
                             const char *context)
{
    if (!agent_id || !action || !resource) {
        CUPOLAS_LOG_ERROR("cupolas_check_permission: null parameter");
        return cupolas_ERR_INVALID_PARAM;
    }

    if (!g_cupolas.initialized || !g_cupolas.perm) {
        CUPOLAS_LOG_ERROR("cupolas_check_permission: not initialized");
        return cupolas_ERR_STATE_ERROR;
    }

    int result = permission_engine_check(g_cupolas.perm, agent_id, action, resource, context);

    if (g_cupolas.audit) {
        audit_logger_log(g_cupolas.audit, AUDIT_EVENT_PERMISSION, agent_id, action, resource, NULL,
                         result >= 0 ? result : -1);
    }

    if (result > 0) {
        guard_context_t guard_ctx = {.operation = "permission_check",
                                     .resource = resource,
                                     .agent_id = agent_id,
                                     .session_id = context,
                                     .input_data = (void *)action,
                                     .input_size = action ? strlen(action) + 1 : 0,
                                     .context_data = NULL,
                                     .timestamp = airy_time_ns()};

        if (guards_blocking(&guard_ctx)) {
            if (g_cupolas.audit) {
                audit_logger_log(g_cupolas.audit, AUDIT_EVENT_PERMISSION, agent_id, "guard_block",
                                 resource, NULL, 0);
            }
            return 0;
        }
    }

    return result > 0 ? 1 : (result == 0 ? 0 : result);
}

int cupolas_add_permission_rule(const char *agent_id, const char *action, const char *resource,
                                int allow, int priority)
{
    if (!g_cupolas.initialized || !g_cupolas.perm) {
        CUPOLAS_LOG_ERROR("cupolas_add_permission_rule: not initialized");
        return cupolas_ERR_STATE_ERROR;
    }

    return permission_engine_add_rule(g_cupolas.perm, agent_id, action, resource, allow, priority);
}

void cupolas_clear_permission_cache(void)
{
    if (!g_cupolas.initialized || !g_cupolas.perm) {
        return;
    }

    permission_engine_clear_cache(g_cupolas.perm);
}

int cupolas_sanitize_input(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        CUPOLAS_LOG_ERROR("cupolas_sanitize_input: null parameter");
        return cupolas_ERR_INVALID_PARAM;
    }

    airy_mtx_lock(&g_cupolas.lock);
    if (!g_cupolas.initialized || !g_cupolas.san) {
        airy_mtx_unlock(&g_cupolas.lock);
        CUPOLAS_LOG_ERROR("cupolas_sanitize_input: not initialized");
        return cupolas_ERR_STATE_ERROR;
    }

    sanitize_result_t result = sanitizer_sanitize(g_cupolas.san, input, output, output_size, NULL);
    airy_mtx_unlock(&g_cupolas.lock);

    if (g_cupolas.audit) {
        audit_logger_log(g_cupolas.audit, AUDIT_EVENT_SANITIZER, "system", "sanitize_input", input,
                         NULL, (int)result);
    }

    if (result == SANITIZE_OK && cupolas_guards_is_enabled()) {
        guard_manager_t *guard_manager = cupolas_guards_get_manager();
        if (guard_manager) {
            guard_result_t results[CUPOLAS_GUARD_MAX_RESULTS];
            size_t actual_results = 0;

            guard_context_t guard_ctx = {.operation = "input_sanitization",
                                         .resource = "sanitizer",
                                         .agent_id = "system",
                                         .session_id = NULL,
                                         .input_data = (void *)output,
                                         .input_size = strlen(output) + 1,
                                         .context_data = NULL,
                                         .timestamp = airy_time_ns()};

            int guard_ret = guard_manager_check_sync(guard_manager, &guard_ctx, results,
                                                     CUPOLAS_GUARD_MAX_RESULTS, &actual_results);
            if (guard_ret == 0) {
                for (size_t i = 0; i < actual_results; i++) {
                    guard_result_t *gr = &results[i];
                    if (gr->risk_level >= RISK_LEVEL_CRITICAL) {
                        output[0] = '\0';
                        if (g_cupolas.audit) {
                            audit_logger_log(g_cupolas.audit, AUDIT_EVENT_SANITIZER, "system",
                                             "guard_block", input, NULL, 0);
                        }
                        return cupolas_ERROR_INVALID_ARG;
                    } else if (gr->risk_level >= RISK_LEVEL_HIGH) {
                        if (g_cupolas.audit) {
                            audit_logger_log(g_cupolas.audit, AUDIT_EVENT_SANITIZER, "system",
                                             "guard_warn", input, NULL, 0);
                        }
                    }
                }
            }
        }
    }

    switch (result) {
    case SANITIZE_OK:
    case SANITIZE_MODIFIED:
        return CUPOLAS_OK;
    case SANITIZE_REJECTED:
        return cupolas_ERR_PERMISSION_DENIED;
    default:
        return cupolas_ERR_STATE_ERROR;
    }
}

int cupolas_execute_command(const char *command, char *const argv[], int *exit_code,
                            char *stdout_buf, size_t stdout_size, char *stderr_buf,
                            size_t stderr_size)
{
    if (!command || !argv) {
        CUPOLAS_LOG_ERROR("cupolas_execute_command: null parameter");
        return cupolas_ERR_INVALID_PARAM;
    }

    airy_mtx_lock(&g_cupolas.lock);
    if (!g_cupolas.initialized) {
        airy_mtx_unlock(&g_cupolas.lock);
        CUPOLAS_LOG_ERROR("cupolas_execute_command: not initialized");
        return cupolas_ERR_STATE_ERROR;
    }

    char cmd_buffer[1024] = {0};
    size_t pos = snprintf(cmd_buffer, sizeof(cmd_buffer), "%s", command);
    for (int i = 0; argv[i] && pos < sizeof(cmd_buffer) - 1; i++) {
        pos += snprintf(cmd_buffer + pos, sizeof(cmd_buffer) - pos, " %s", argv[i]);
    }

    guard_context_t guard_ctx = {.operation = "command_execution",
                                 .resource = "workbench",
                                 .agent_id = "system",
                                 .session_id = NULL,
                                 .input_data = cmd_buffer,
                                 .input_size = strlen(cmd_buffer) + 1,
                                 .context_data = NULL,
                                 .timestamp = airy_time_ns()};

    if (guards_blocking(&guard_ctx)) {
        if (g_cupolas.audit) {
            audit_logger_log(g_cupolas.audit, AUDIT_EVENT_WORKBENCH, "system", "execute_command",
                             command, "guard_block", cupolas_ERR_PERMISSION_DENIED);
        }
        airy_mtx_unlock(&g_cupolas.lock);
        return cupolas_ERR_PERMISSION_DENIED;
    }

    workbench_config_t wbcfg;
    workbench_default_config(&wbcfg);

    if (!g_cupolas.wb) {
        g_cupolas.wb = workbench_create(&wbcfg);
        if (!g_cupolas.wb) {
            airy_mtx_unlock(&g_cupolas.lock);
            return cupolas_ERR_OUT_OF_MEMORY;
        }
    }

    workbench_result_t result;
    int ret = workbench_execute(g_cupolas.wb, command, argv, &result);

    if (exit_code) {
        *exit_code = result.exit_code;
    }

    if (stdout_buf && stdout_size > 0 && result.stdout_data) {
        AIRY_STRNCPY_TERM(stdout_buf, result.stdout_data, stdout_size);
    }

    if (stderr_buf && stderr_size > 0 && result.stderr_data) {
        AIRY_STRNCPY_TERM(stderr_buf, result.stderr_data, stderr_size);
    }

    workbench_result_free(&result);

    if (g_cupolas.audit) {
        audit_logger_log(g_cupolas.audit, AUDIT_EVENT_WORKBENCH, "system", "execute_command",
                         command, NULL, ret);
    }

    airy_mtx_unlock(&g_cupolas.lock);
    return ret;
}

void cupolas_flush_audit_log(void)
{
    if (!g_cupolas.initialized || !g_cupolas.audit) {
        return;
    }

    audit_logger_flush(g_cupolas.audit);
}
