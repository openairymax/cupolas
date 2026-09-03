/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * Process / Pipe primitives (cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_PROCESS_H
#define cupolas_PLATFORM_PROCESS_H

#include "platform_base.h"
#include "sandbox.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Process Primitives
 * ============================================================================ */

/* Process Handle Types */
#if cupolas_PLATFORM_WINDOWS
typedef HANDLE cupolas_process_t;
typedef DWORD cupolas_pid_t;
/* Windows 下与 POSIX int[2] 对齐：{read, write} 两端相邻存放。
 * （此前 typedef HANDLE 单值，cupolas_pipe_create 却写入两把 HANDLE，
 * 会越界覆盖相邻结构体字段，MSVC 下还报 C2036。） */
typedef HANDLE cupolas_pipe_t[2];
#else
typedef pid_t cupolas_pid_t;
typedef int cupolas_process_t;
typedef int cupolas_pipe_t[2];
#endif

/* Process Exit Status */
typedef struct cupolas_exit_status {
    int code;
    bool signaled;
    int signal;
} cupolas_exit_status_t;

/* Process Attributes */
typedef struct cupolas_process_attr {
    const char *working_dir;
    const char **env;
    bool redirect_stdin;
    bool redirect_stdout;
    bool redirect_stderr;
    cupolas_pipe_t stdin_pipe;
    cupolas_pipe_t stdout_pipe;
    cupolas_pipe_t stderr_pipe;
    const cupolas_sandbox_t *sandbox; /* 原生沙箱（S-7）；NULL = 不启用 */
} cupolas_process_attr_t;

/* Process Interface */
/**
 * @brief Spawn child process
 * @param[out] proc Process handle output (must not be NULL)
 * @param[in] path Path to executable (must not be NULL)
 * @param[in] argv Argument vector (NULL-terminated, must not be NULL)
 * @param[in] attr Process attributes (may be NULL for defaults)
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership proc: callee initializes, caller owns
 */
int cupolas_process_spawn(cupolas_process_t *proc, const char *path, char *const argv[],
                          const cupolas_process_attr_t *attr);

/**
 * @brief Wait for process
 * @param[in] proc Process handle
 * @param[out] status Exit status output (must not be NULL)
 * @param[in] timeout_ms Timeout in milliseconds (0 for infinite)
 * @return 0 on success, cupolas_ERROR_TIMEOUT on timeout, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership status: callee writes, caller owns
 */
int cupolas_process_wait(cupolas_process_t proc, cupolas_exit_status_t *status,
                         uint32_t timeout_ms);

/**
 * @brief Terminate process
 * @param[in] proc Process handle
 * @param[in] signal Signal to send (platform-specific)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_process_terminate(cupolas_process_t proc, int signal);

/**
 * @brief Close process handle
 * @param[in] proc Process handle
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_process_close(cupolas_process_t proc);

/**
 * @brief Get process ID
 * @param[in] proc Process handle
 * @return Process ID
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
cupolas_pid_t cupolas_process_getpid(cupolas_process_t proc);

/* Pipe Interface */
/**
 * @brief Create pipe
 * @param[out] pipe Pipe handles output (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership pipe: callee initializes, caller owns
 */
int cupolas_pipe_create(cupolas_pipe_t *pipe);

/**
 * @brief Close pipe
 * @param[in] pipe Pipe handles
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_pipe_close(cupolas_pipe_t *pipe);

/**
 * @brief Close the read end of a pipe, keep the write end usable
 * @param[in] pipe Pipe handles
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @note Parent 在 spawn 后关闭自己持有的子进程写入端/读取端副本时使用
 *       （见 workbench.c P2-5：只关一端才能让 read 看到 EOF）。
 */
int cupolas_pipe_close_read_end(cupolas_pipe_t *pipe);

/**
 * @brief Close the write end of a pipe, keep the read end usable
 * @param[in] pipe Pipe handles
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_pipe_close_write_end(cupolas_pipe_t *pipe);

/**
 * @brief Read from pipe
 * @param[in] pipe Pipe handle
 * @param[out] buf Buffer to read into (must not be NULL)
 * @param[in] count Number of bytes to read
 * @param[out] bytes_read Bytes actually read (may be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership buf: caller owns; bytes_read: callee writes if not NULL
 */
int cupolas_pipe_read(cupolas_pipe_t *pipe, void *buf, size_t count, size_t *bytes_read);

/**
 * @brief Write to pipe
 * @param[in] pipe Pipe handle
 * @param[in] buf Data to write (must not be NULL)
 * @param[in] count Number of bytes to write
 * @param[out] bytes_written Bytes actually written (may be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership buf: caller retains; bytes_written: callee writes if not NULL
 */
int cupolas_pipe_write(cupolas_pipe_t *pipe, const void *buf, size_t count, size_t *bytes_written);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_PROCESS_H */
