/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * sandbox.h - Native Execution Sandbox (S-7 convergence: Landlock + seccomp)
 *
 * S-7 (0.1.2): 沙箱去 docker 化。docker 容器运行时（workbench_container.c）
 * 已移出构建；原生进程模式（workbench.c fork/execvp + workbench_limits）
 * 为本体。本模块在 Linux 上叠加 Landlock（文件系统规则）+ seccomp
 * （syscall BPF 过滤）两层原生沙箱，替代外部 docker 的隔离语义。
 *
 * 使用方式：workbench_config_t.sandbox 配置（或直接作为
 * cupolas_process_attr_t.sandbox 传入 spawn），fork 子进程在 exec 前
 * 应用（见 platform_process.c）。enabled=0（默认）时为零开销 no-op，
 * 完全向后兼容；非 Linux 平台（macOS/Windows）也为 no-op，进程隔离
 * 由各平台原生机制承担。
 *
 * 安全模型（默认只读）：
 *   - Landlock：restrict 后进程只能访问显式允许的路径。默认允许
 *     "/" 只读（读文件/读目录/执行），rw_paths 列表叠加读写权限，
 *     ro_paths 叠加额外只读路径。
 *   - seccomp：deny-list 拦截特权/危险 syscall（ptrace、模块加载、
 *     内核执行、进程内存写入等）；deny_network=1 时额外拦截网络族。
 */

#ifndef CUPOLAS_SANDBOX_H
#define CUPOLAS_SANDBOX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Native execution sandbox configuration.
 *
 * @note Thread-safe: N/A (const configuration)
 * @note 仅 Linux 生效；macOS/Windows 恒为 no-op。
 */
typedef struct cupolas_sandbox {
    int enabled;                 /* 0 = disabled（默认，零开销 no-op） */
    int deny_network;            /* 1 = seccomp 拦截 network syscall 族 */
    const char *const *ro_paths; /* Landlock 追加只读路径（NULL 结尾数组，可 NULL） */
    const char *const *rw_paths; /* Landlock 读写路径（NULL 结尾数组，可 NULL） */
} cupolas_sandbox_t;

/**
 * @brief Initialize a sandbox config to the disabled default.
 * @param sb [in/out] sandbox config (must not be NULL)
 */
void cupolas_sandbox_init(cupolas_sandbox_t *sb);

/**
 * @brief Apply the sandbox to the current process (fork child, pre-exec).
 *
 * Linux: enabled=1 时应用 Landlock 规则 + seccomp filter。成功后当前
 * 进程无法回退。enabled=0 或非 Linux 平台返回 0（no-op）。
 *
 * @param sb [in] sandbox config (may be NULL -> no-op)
 * @return 0 = applied or no-op; non-zero = application failed（调用方
 *         应终止 exec 并上报）
 * @note Thread-safe: N/A（仅 fork 子进程单线程上下文调用）
 */
int cupolas_sandbox_apply(const cupolas_sandbox_t *sb);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_SANDBOX_H */
