// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform_process.c - Cross-Platform Abstraction Layer (Process and Pipe)
 */

/**
 * @file platform_process.c
 * @brief cupolas 平台抽象层 - 进程与管道域
 *
 * 本文件实现进程派生/等待/终止/关闭/PID 查询与匿名管道读写。
 */

#include "platform.h"
#include "platform_internal.h"

#include "atomic_compat.h"
#include "airy_memory.h"
#include "string_compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include "airy_mman.h"
#endif

#if cupolas_PLATFORM_WINDOWS
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#define getcwd _getcwd
#define rmdir _rmdir
#define unlink _unlink
#define access _access /* flawfinder: ignore */
#define F_OK 0
#define W_OK 2
#define R_OK 4
#else
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#include "error.h"

extern char **environ;

/* ============================================================================
 * Process Implementation
 * ============================================================================ */

int cupolas_process_spawn(cupolas_process_t *proc, const char *path, char *const argv[],
                          const cupolas_process_attr_t *attr)
{
    if (!proc || !path || !argv)
        return cupolas_ERROR_INVALID_ARG;

#if cupolas_PLATFORM_WINDOWS
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    if (attr) {
        /* cupolas_pipe_t 在 Windows 下为 HANDLE[2]：{read, write}。
         * 子进程 stdin 用读端 [0]；stdout/stderr 用写端 [1]。 */
        if (attr->redirect_stdin && attr->stdin_pipe[0] != INVALID_HANDLE_VALUE)
            si.hStdInput = attr->stdin_pipe[0];
        if (attr->redirect_stdout && attr->stdout_pipe[1] != INVALID_HANDLE_VALUE)
            si.hStdOutput = attr->stdout_pipe[1];
        if (attr->redirect_stderr && attr->stderr_pipe[1] != INVALID_HANDLE_VALUE)
            si.hStdError = attr->stderr_pipe[1];
    }

    PROCESS_INFORMATION pi = {0};
    char cmdLine[4096] = {0};
    size_t offset = 0;

    for (int i = 0; argv[i] != NULL; i++) {
        size_t len = strlen(argv[i]);
        if (offset + len + 2 > sizeof(cmdLine))
            return cupolas_ERROR_OVERFLOW;
        if (i > 0)
            cmdLine[offset++] = ' ';
        __builtin_memcpy(cmdLine + offset, argv[i], len);
        offset += len;
    }
    cmdLine[offset] = '\0';

    const char *working_dir = (attr && attr->working_dir) ? attr->working_dir : NULL;
    LPVOID env_block = NULL;
    if (attr && attr->env) {
        env_block = (LPVOID)attr->env;
    }

    BOOL ok = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, env_block,
                             working_dir, &si, &pi);
    if (!ok)
        return cupolas_ERROR_IO;

    *proc = pi.hProcess;
    CloseHandle(pi.hThread);
    return 0;
#else
    pid_t pid = fork();
    if (pid < 0)
        return cupolas_ERROR_IO;
    if (pid == 0) {
        if (attr) {
            if (attr->working_dir) {
                if (chdir(attr->working_dir) != 0) {
                    _exit(126);
                }
            }
            if (attr->redirect_stdin && attr->stdin_pipe[0] >= 0) {
                dup2(attr->stdin_pipe[0], STDIN_FILENO);
                close(attr->stdin_pipe[1]);
            }
            if (attr->redirect_stdout && attr->stdout_pipe[1] >= 0) {
                close(attr->stdout_pipe[0]);
                dup2(attr->stdout_pipe[1], STDOUT_FILENO);
                close(attr->stdout_pipe[1]);
            }
            if (attr->redirect_stderr && attr->stderr_pipe[1] >= 0) {
                close(attr->stderr_pipe[0]);
                dup2(attr->stderr_pipe[1], STDERR_FILENO);
                close(attr->stderr_pipe[1]);
            }
            if (attr->env) {
                environ = (char **)attr->env;
            }
        }
        /* S-7 原生沙箱（Landlock + seccomp）：在 exec 前应用；失败则终止
         * exec（exit 126 = "命令可执行但无法运行"）。非 Linux 为 no-op。 */
        if (attr->sandbox && attr->sandbox->enabled) {
            if (cupolas_sandbox_apply(attr->sandbox) != 0) {
                _exit(126);
            }
        }
        if (attr && attr->env) {
            execve(path, argv, (char *const *)attr->env);
        } else {
            execvp(path, argv);
        }
        _exit(127);
    }
    *proc = pid;
    return 0;
#endif
}

int cupolas_process_wait(cupolas_process_t proc, cupolas_exit_status_t *status, uint32_t timeout_ms)
{
    if (!status)
        return cupolas_ERROR_INVALID_ARG;

#if cupolas_PLATFORM_WINDOWS
    DWORD ms = (timeout_ms == 0) ? INFINITE : (DWORD)timeout_ms;
    DWORD result = WaitForSingleObject(proc, ms);
    if (result == WAIT_TIMEOUT)
        return cupolas_ERROR_TIMEOUT;
    if (result != WAIT_OBJECT_0)
        return cupolas_ERROR_IO;

    DWORD exit_code;
    GetExitCodeProcess(proc, &exit_code);
    status->code = (int)exit_code;
    status->signaled = false;
    status->signal = 0;
    return 0;
#else
    if (timeout_ms == 0) {
        int s;
        pid_t ret = waitpid(proc, &s, 0);
        if (ret < 0)
            return cupolas_ERROR_IO;
        status->signaled = WIFSIGNALED(s);
        status->signal = WTERMSIG(s);
        status->code = WEXITSTATUS(s);
        return 0;
    } else {
        for (uint32_t elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
            int s;
            pid_t ret = waitpid(proc, &s, WNOHANG);
            if (ret > 0) {
                status->signaled = WIFSIGNALED(s);
                status->signal = WTERMSIG(s);
                status->code = WEXITSTATUS(s);
                return 0;
            }
            if (ret < 0 && errno != ECHILD)
                return cupolas_ERROR_IO;
            usleep(10000);
        }
        return cupolas_ERROR_TIMEOUT;
    }
#endif
}

int cupolas_process_terminate(cupolas_process_t proc, int signal)
{
#if cupolas_PLATFORM_WINDOWS
    (void)signal;
    return TerminateProcess(proc, 1) ? 0 : -1;
#else
    return kill(proc, signal) == 0 ? 0 : -1;
#endif
}

int cupolas_process_close(cupolas_process_t proc)
{
#if cupolas_PLATFORM_WINDOWS
    return CloseHandle(proc) ? 0 : -1;
#else
    (void)proc;
    return 0;
#endif
}

cupolas_pid_t cupolas_process_getpid(cupolas_process_t proc)
{
#if cupolas_PLATFORM_WINDOWS
    return GetProcessId(proc);
#else
    return proc;
#endif
}

/* ============================================================================
 * Pipe Implementation
 * ============================================================================ */

int cupolas_pipe_create(cupolas_pipe_t *pfd)
{
#if cupolas_PLATFORM_WINDOWS
    HANDLE readHandle, writeHandle;
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};

    if (!CreatePipe(&readHandle, &writeHandle, &sa, 0))
        return cupolas_ERROR_IO;
    (*pfd)[0] = readHandle;
    (*pfd)[1] = writeHandle;
    return 0;
#else
    return pipe(*pfd) == 0 ? 0 : cupolas_ERROR_IO;
#endif
}

int cupolas_pipe_close(cupolas_pipe_t *pipe)
{
#if cupolas_PLATFORM_WINDOWS
    if ((*pipe)[0] != INVALID_HANDLE_VALUE)
        CloseHandle((*pipe)[0]);
    if ((*pipe)[1] != INVALID_HANDLE_VALUE)
        CloseHandle((*pipe)[1]);
    (*pipe)[0] = INVALID_HANDLE_VALUE;
    (*pipe)[1] = INVALID_HANDLE_VALUE;
    return 0;
#else
    if ((*pipe)[0] >= 0)
        close((*pipe)[0]);
    if ((*pipe)[1] >= 0)
        close((*pipe)[1]);
    (*pipe)[0] = -1;
    (*pipe)[1] = -1;
    return 0;
#endif
}

int cupolas_pipe_close_read_end(cupolas_pipe_t *pipe)
{
#if cupolas_PLATFORM_WINDOWS
    if ((*pipe)[0] != INVALID_HANDLE_VALUE) {
        CloseHandle((*pipe)[0]);
        (*pipe)[0] = INVALID_HANDLE_VALUE;
    }
#else
    if ((*pipe)[0] >= 0) {
        close((*pipe)[0]);
        (*pipe)[0] = -1;
    }
#endif
    return 0;
}

int cupolas_pipe_close_write_end(cupolas_pipe_t *pipe)
{
#if cupolas_PLATFORM_WINDOWS
    if ((*pipe)[1] != INVALID_HANDLE_VALUE) {
        CloseHandle((*pipe)[1]);
        (*pipe)[1] = INVALID_HANDLE_VALUE;
    }
#else
    if ((*pipe)[1] >= 0) {
        close((*pipe)[1]);
        (*pipe)[1] = -1;
    }
#endif
    return 0;
}

int cupolas_pipe_read(cupolas_pipe_t *pipe, void *buf, size_t count, size_t *bytes_read)
{
#if cupolas_PLATFORM_WINDOWS
    DWORD bytesRead = 0;
    BOOL ok = ReadFile((*pipe)[0], buf, (DWORD)count, &bytesRead, NULL);
    if (bytes_read)
        *bytes_read = bytesRead;
    return ok ? 0 : cupolas_ERROR_IO;
#else
    ssize_t n = read((*pipe)[0], buf, count);
    if (n < 0)
        return cupolas_ERROR_IO;
    if (bytes_read)
        *bytes_read = (size_t)n;
    return 0;
#endif
}

int cupolas_pipe_write(cupolas_pipe_t *pipe, const void *buf, size_t count, size_t *bytes_written)
{
#if cupolas_PLATFORM_WINDOWS
    DWORD written = 0;
    BOOL ok = WriteFile((*pipe)[1], buf, (DWORD)count, &written, NULL);
    if (bytes_written)
        *bytes_written = written;
    return ok ? 0 : cupolas_ERROR_IO;
#else
    ssize_t n = write((*pipe)[1], buf, count);
    if (n < 0)
        return cupolas_ERROR_IO;
    if (bytes_written)
        *bytes_written = (size_t)n;
    return 0;
#endif
}
