// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * workbench_process_core.c - Cross-platform Process Management Implementation
 */

/**
 * @file workbench_process_core.c
 * @brief Cross-platform Process Management Implementation
 * @author SPHARX Ltd. - Airymax Team
 * @date 2024
 */

#include "utils/cupolas_utils.h"
#include "workbench_process.h"

#include <stdlib.h>
#include <string.h>

#if cupolas_PLATFORM_WINDOWS
#include <fcntl.h>
#include <io.h>
#include <process.h>

int cupolas_process_spawn(cupolas_process_t *proc, const char *path, char *const argv[],
                          const cupolas_process_attr_t *attr)
{
    if (!proc || !path)
        return cupolas_ERROR_INVALID_ARG;

    HANDLE hStdinRead = NULL, hStdinWrite = NULL;
    HANDLE hStdoutRead = NULL, hStdoutWrite = NULL;
    HANDLE hStderrRead = NULL, hStderrWrite = NULL;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (attr && attr->redirect_stdin) {
        if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
            return cupolas_ERROR_IO;
        }
        SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    }

    if (attr && attr->redirect_stdout) {
        if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
            if (hStdinRead)
                CloseHandle(hStdinRead);
            if (hStdinWrite)
                CloseHandle(hStdinWrite);
            return cupolas_ERROR_IO;
        }
        SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    }

    if (attr && attr->redirect_stderr) {
        if (!CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
            if (hStdinRead)
                CloseHandle(hStdinRead);
            if (hStdinWrite)
                CloseHandle(hStdinWrite);
            if (hStdoutRead)
                CloseHandle(hStdoutRead);
            if (hStdoutWrite)
                CloseHandle(hStdoutWrite);
            return cupolas_ERROR_IO;
        }
        SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    __builtin_memset(&si, 0, sizeof(si));
    __builtin_memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;

    si.hStdInput = hStdinRead ? hStdinRead : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hStdoutWrite ? hStdoutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = hStderrWrite ? hStderrWrite : GetStdHandle(STD_ERROR_HANDLE);

    char cmdline[32768];
    size_t len = 0;
    cmdline[0] = '\0';

    const char *p = path;
    while (*p && len < sizeof(cmdline) - 2) {
        if (*p == ' ' || *p == '\t') {
            cmdline[len++] = '"';
            while (*p && len < sizeof(cmdline) - 1) {
                cmdline[len++] = *p++;
            }
            cmdline[len++] = '"';
        } else {
            cmdline[len++] = *p++;
        }
    }

    if (argv) {
        for (int i = 0; argv[i] && len < sizeof(cmdline) - 2; i++) {
            cmdline[len++] = ' ';
            const char *arg = argv[i];
            int need_quote = (strchr(arg, ' ') || strchr(arg, '\t'));
            if (need_quote)
                cmdline[len++] = '"';
            while (*arg && len < sizeof(cmdline) - 1) {
                cmdline[len++] = *arg++;
            }
            if (need_quote)
                cmdline[len++] = '"';
        }
    }
    cmdline[len] = '\0';

    DWORD creationFlags = CREATE_NO_WINDOW;
    BOOL success = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, creationFlags, NULL,
                                  attr && attr->working_dir ? attr->working_dir : NULL, &si, &pi);

    if (hStdinRead)
        CloseHandle(hStdinRead);
    if (hStdoutWrite)
        CloseHandle(hStdoutWrite);
    if (hStderrWrite)
        CloseHandle(hStderrWrite);

    if (!success) {
        if (hStdinWrite)
            CloseHandle(hStdinWrite);
        if (hStdoutRead)
            CloseHandle(hStdoutRead);
        if (hStderrRead)
            CloseHandle(hStderrRead);
        return cupolas_ERROR_IO;
    }

    CloseHandle(pi.hThread);

    if (attr && attr->redirect_stdin) {
        attr->stdin_pipe = hStdinWrite;
    }
    if (attr && attr->redirect_stdout) {
        attr->stdout_pipe = hStdoutRead;
    }
    if (attr && attr->redirect_stderr) {
        attr->stderr_pipe = hStderrRead;
    }

    *proc = pi.hProcess;
    return cupolas_OK;
}

int cupolas_process_wait(cupolas_process_t proc, cupolas_exit_status_t *status, uint32_t timeout_ms)
{
    if (!proc || !status)
        return cupolas_ERROR_INVALID_ARG;

    DWORD wait_time = timeout_ms > 0 ? timeout_ms : INFINITE;
    DWORD result = WaitForSingleObject(proc, wait_time);

    if (result == WAIT_TIMEOUT) {
        return cupolas_ERROR_TIMEOUT;
    }

    if (result != WAIT_OBJECT_0) {
        return cupolas_ERROR_UNKNOWN;
    }

    DWORD exit_code;
    if (!GetExitCodeProcess(proc, &exit_code)) {
        return cupolas_ERROR_UNKNOWN;
    }

    status->code = (int)exit_code;
    status->signaled = false;
    status->signal = 0;

    return cupolas_OK;
}

int cupolas_process_terminate(cupolas_process_t proc, int signal)
{
    (void)signal;
    if (!proc)
        return cupolas_ERROR_INVALID_ARG;

    return TerminateProcess(proc, 1) ? cupolas_OK : cupolas_ERROR_UNKNOWN;
}

int cupolas_process_close(cupolas_process_t proc)
{
    if (!proc)
        return cupolas_ERROR_INVALID_ARG;

    CloseHandle(proc);
    return cupolas_OK;
}

cupolas_pid_t cupolas_process_getpid(cupolas_process_t proc)
{
    if (!proc)
        return 0;
    return GetProcessId(proc);
}

#else

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief 子进程设置函数
 */
static void setup_child_process(int *stdin_pipe, int *stdout_pipe, int *stderr_pipe,
                                const cupolas_process_attr_t *attr, const char *path,
                                char *const argv[])
{
    if (attr && attr->working_dir) {
        if (chdir(attr->working_dir) != 0) {
            _exit(127);
        }
    }

    if (stdin_pipe[0] >= 0) {
        dup2(stdin_pipe[0], STDIN_FILENO);
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
    }

    if (stdout_pipe[1] >= 0) {
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
    }

    if (stderr_pipe[1] >= 0) {
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
    }

    for (int fd = 3; fd < 1024; fd++) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    execvp(path ? path : NULL,
           argv ? argv : NULL); /* flawfinder: ignore - path/argv validated by caller */
    _exit(127);
}

int cupolas_process_spawn(cupolas_process_t *proc, const char *path, char *const argv[],
                          const cupolas_process_attr_t *attr)
{
    if (!proc || !path)
        return cupolas_ERROR_INVALID_ARG;

    int stdin_pipe[2] = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    /* P2-5 (cupolas_d): 复用调用方（workbench）预创建并经 attr 传入的管道，
     * 使子进程 stdout/stderr 直接流入父进程持有的读端。修复原实现：
     * 1) 本地创建管道却在父进程侧关闭读端，子进程输出无人读取（丢失/触发
     *    SIGPIPE）；
     * 2) 父进程自持 stdout/stderr 写端，阻塞读因永不 EOF 而永久挂起。 */
    if (attr && attr->redirect_stdin) {
        __builtin_memcpy(stdin_pipe, attr->stdin_pipe, sizeof(stdin_pipe));
    }
    if (attr && attr->redirect_stdout) {
        __builtin_memcpy(stdout_pipe, attr->stdout_pipe, sizeof(stdout_pipe));
    }
    if (attr && attr->redirect_stderr) {
        __builtin_memcpy(stderr_pipe, attr->stderr_pipe, sizeof(stderr_pipe));
    }

    pid_t pid = fork();

    if (pid < 0) {
        return cupolas_ERROR_UNKNOWN;
    }

    if (pid == 0) {
        setup_child_process(stdin_pipe, stdout_pipe, stderr_pipe, attr, path, argv);
    }

    /* 父进程侧不在此关闭 stdout/stderr 写端：管道归 workbench 所有，
     * 由 workbench 在 spawn 返回后统一关闭（关闭写端后子进程退出即可 EOF，
     * 阻塞读正常返回）。 */
    *proc = pid;
    return cupolas_OK;
}

int cupolas_process_wait(cupolas_process_t proc, cupolas_exit_status_t *status, uint32_t timeout_ms)
{
    if (!status)
        return cupolas_ERROR_INVALID_ARG;

    if (timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        while (tv.tv_sec > 0 || tv.tv_usec > 0) {
            int result = waitpid(proc, &status->code, WNOHANG);
            if (result > 0) {
                if (WIFEXITED(status->code)) {
                    status->code = WEXITSTATUS(status->code);
                    status->signaled = false;
                    status->signal = 0;
                } else if (WIFSIGNALED(status->code)) {
                    status->signal = WTERMSIG(status->code);
                    status->signaled = true;
                    status->code = -1;
                }
                return cupolas_OK;
            } else if (result < 0 && errno == ECHILD) {
                return cupolas_ERROR_UNKNOWN;
            }

            struct timeval start, end;
            gettimeofday(&start, NULL);

            fd_set dummy;
            FD_ZERO(&dummy);
            select(0, &dummy, NULL, NULL, &tv);

            gettimeofday(&end, NULL);
            long elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
            long remaining_us = tv.tv_sec * 1000000 + tv.tv_usec - elapsed_us;
            if (remaining_us <= 0)
                break;
            tv.tv_sec = remaining_us / 1000000;
            tv.tv_usec = remaining_us % 1000000;
        }
        return cupolas_ERROR_TIMEOUT;
    }

    int result = waitpid(proc, &status->code, 0);
    if (result < 0) {
        return cupolas_ERROR_UNKNOWN;
    }

    if (WIFEXITED(status->code)) {
        status->code = WEXITSTATUS(status->code);
        status->signaled = false;
        status->signal = 0;
    } else if (WIFSIGNALED(status->code)) {
        status->signal = WTERMSIG(status->code);
        status->signaled = true;
        status->code = -1;
    }

    return cupolas_OK;
}

int cupolas_process_terminate(cupolas_process_t proc, int signal)
{
    if (proc <= 0)
        return cupolas_ERROR_INVALID_ARG;

    return kill(proc, signal > 0 ? signal : SIGTERM) == 0 ? cupolas_OK : cupolas_ERROR_UNKNOWN;
}

int cupolas_process_close(cupolas_process_t proc)
{
    if (proc <= 0)
        return cupolas_ERROR_INVALID_ARG;

#ifndef cupolas_PLATFORM_WINDOWS
    int status = 0;
    pid_t result;
    do {
        result = waitpid(proc, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);
#endif

    (void)proc;
    return cupolas_OK;
}

cupolas_pid_t cupolas_process_getpid(cupolas_process_t proc)
{
    return proc;
}

#endif
