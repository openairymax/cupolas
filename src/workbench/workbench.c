// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file workbench.c
 * @brief Secure workbench: cross-platform process management.
 *
 * Process lifecycle delegates to the commons platform layer:
 * airy_process_spawn wires the stdio pipes internally and half-closes
 * the child ends in the parent, so capture readers observe EOF unaided.
 * Negative exit codes encode signal termination (-signum) per the
 * platform wait convention.
 */

#include "platform.h"
#include "cupolas.h"
#include "workbench.h"
#include "security/cupolas_error.h"

#include "utils/cupolas_utils.h"

#include <stdlib.h>
#include <string.h>

#define DEFAULT_TIMEOUT_MS 30000
#define DEFAULT_MAX_OUTPUT_SIZE (1024 * 1024)
#define OUTPUT_CHUNK_SIZE 4096

struct workbench {
    workbench_config_t manager;
    workbench_state_t state;
    airy_process_info_t process;
    char *stdout_buf;
    size_t stdout_capacity;
    size_t stdout_size;
    char *stderr_buf;
    size_t stderr_capacity;
    size_t stderr_size;
    uint64_t start_time_ms;
    airy_mtx_t lock;
};

void workbench_default_config(workbench_config_t *manager)
{
    if (!manager)
        return;

    __builtin_memset(manager, 0, sizeof(workbench_config_t));
    manager->timeout_ms = DEFAULT_TIMEOUT_MS;
    manager->max_output_size = DEFAULT_MAX_OUTPUT_SIZE;
    manager->redirect_stdin = true;
    manager->redirect_stdout = true;
    manager->redirect_stderr = true;
}

workbench_t *workbench_create(const workbench_config_t *manager)
{
    workbench_t *wb = (workbench_t *)AIRY_CALLOC(1, sizeof(workbench_t));
    if (!wb)
        return NULL;

    if (manager) {
        __builtin_memcpy(&wb->manager, manager, sizeof(workbench_config_t));
    } else {
        workbench_default_config(&wb->manager);
    }

    if (airy_mtx_init(&wb->lock) != cupolas_OK) {
        AIRY_FREE(wb);
        return NULL;
    }

    wb->state = WORKBENCH_STATE_IDLE;

    if (wb->manager.max_output_size > 0) {
        wb->stdout_capacity = wb->manager.max_output_size;
        wb->stdout_buf = (char *)AIRY_CALLOC(1, wb->stdout_capacity);

        wb->stderr_capacity = wb->manager.max_output_size;
        wb->stderr_buf = (char *)AIRY_CALLOC(1, wb->stderr_capacity);
    }

    return wb;
}

void workbench_destroy(workbench_t *wb)
{
    if (!wb)
        return;

    airy_mtx_lock(&wb->lock);

    if (wb->state == WORKBENCH_STATE_RUNNING)
        workbench_terminate(wb);

    AIRY_FREE(wb->stdout_buf);
    AIRY_FREE(wb->stderr_buf);

    airy_mtx_unlock(&wb->lock);
    airy_mtx_destroy(&wb->lock);
    AIRY_FREE(wb);
}

/*
 * Drain one capture pipe until EOF; bytes beyond the capture capacity
 * are dropped (keeps the child unblocked on oversized output).
 */
static void wb_drain_pipe(int fd, char *buf, size_t *size, size_t capacity)
{
    char chunk[OUTPUT_CHUNK_SIZE];

    while (fd >= 0) {
        long n = airy_pipe_read(fd, chunk, sizeof(chunk));
        if (n <= 0)
            break;
        if (*size + (size_t)n < capacity) {
            __builtin_memcpy(buf + *size, chunk, (size_t)n);
            *size += (size_t)n;
        }
    }
}

static void wb_read_output(workbench_t *wb)
{
    if (wb->manager.redirect_stdout && wb->stdout_buf)
        wb_drain_pipe(wb->process.stdout_fd, wb->stdout_buf,
                      &wb->stdout_size, wb->stdout_capacity);

    if (wb->manager.redirect_stderr && wb->stderr_buf)
        wb_drain_pipe(wb->process.stderr_fd, wb->stderr_buf,
                      &wb->stderr_size, wb->stderr_capacity);
}

static void wb_fill_result(workbench_t *wb, workbench_result_t *result,
                           int exit_code, bool signaled, int sig,
                           bool timed_out)
{
    __builtin_memset(result, 0, sizeof(workbench_result_t));
    result->exit_code = exit_code;
    result->signaled = signaled;
    result->signal = sig;
    result->timed_out = timed_out;
    result->stdout_data = wb->stdout_buf ? AIRY_STRDUP(wb->stdout_buf) : NULL;
    result->stdout_size = wb->stdout_size;
    result->stderr_data = wb->stderr_buf ? AIRY_STRDUP(wb->stderr_buf) : NULL;
    result->stderr_size = wb->stderr_size;
    result->start_time_ms = wb->start_time_ms;
    result->end_time_ms = airy_time_wall_ms();
}

/* Platform wait encodes signals as negative exit codes; decode back. */
static void wb_fill_status(workbench_t *wb, workbench_result_t *result,
                           int exit_code)
{
    if (exit_code < 0)
        wb_fill_result(wb, result, 0, true, -exit_code, false);
    else
        wb_fill_result(wb, result, exit_code, false, 0, false);
}

static void wb_fill_opt(workbench_t *wb, airy_process_opt_t *opt)
{
    __builtin_memset(opt, 0, sizeof(*opt));
    opt->working_dir = wb->manager.working_dir;
    opt->redirect_stdin = wb->manager.redirect_stdin;
    opt->redirect_stdout = wb->manager.redirect_stdout;
    opt->redirect_stderr = wb->manager.redirect_stderr;
    /* 原生沙箱：enabled 时才传递给 spawn（否则保持 NULL） */
    if (wb->manager.sandbox.enabled)
        opt->sandbox = &wb->manager.sandbox;
}

/*
 * Shared spawn primitive for the sync/async entry points. Holds the lock
 * across the whole start sequence and always releases it before returning.
 * airy_process_spawn owns the stdio pipes and drops the child ends in the
 * parent, so no manual half-close is needed here (P2-5 moved into the
 * platform layer). reset_buf clears the capture buffer heads; only the
 * sync path needs it.
 */
static int wb_start(workbench_t *wb, const char *command,
                    char *const argv[], bool reset_buf)
{
    if (!wb || !command)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (wb->state == WORKBENCH_STATE_RUNNING) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_BUSY;
    }

    wb->stdout_size = 0;
    wb->stderr_size = 0;
    if (reset_buf) {
        if (wb->stdout_buf)
            wb->stdout_buf[0] = '\0';
        if (wb->stderr_buf)
            wb->stderr_buf[0] = '\0';
    }

    airy_process_opt_t opt;
    wb_fill_opt(wb, &opt);

    wb->start_time_ms = airy_time_wall_ms();

    if (airy_process_spawn(command, argv, &opt, &wb->process) != 0) {
        wb->state = WORKBENCH_STATE_ERROR;
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_IO;
    }

    wb->state = WORKBENCH_STATE_RUNNING;
    airy_mtx_unlock(&wb->lock);
    return cupolas_OK;
}

int workbench_execute(workbench_t *wb, const char *command,
                      char *const argv[], workbench_result_t *result)
{
    int ret = wb_start(wb, command, argv, true);
    if (ret != cupolas_OK)
        return ret;

    int exit_code = 0;
    bool timed_out = false;

    ret = airy_process_wait(&wb->process, wb->manager.timeout_ms, &exit_code);
    if (ret == AIRY_ERR_TIMEOUT) {
        timed_out = true;
        airy_process_kill(&wb->process);
        airy_process_wait(&wb->process, 1000, &exit_code);
    }

    wb_read_output(wb);
    airy_process_close_pipes(&wb->process);

    airy_mtx_lock(&wb->lock);
    if (timed_out)
        wb_fill_result(wb, result, -1, false, 0, true);
    else
        wb_fill_status(wb, result, exit_code);
    wb->state = timed_out ? WORKBENCH_STATE_STOPPED : WORKBENCH_STATE_IDLE;
    airy_mtx_unlock(&wb->lock);

    return timed_out ? cupolas_ERROR_TIMEOUT : cupolas_OK;
}

int workbench_execute_async(workbench_t *wb, const char *command,
                            char *const argv[])
{
    return wb_start(wb, command, argv, false);
}

int workbench_wait(workbench_t *wb, workbench_result_t *result,
                   uint32_t timeout_ms)
{
    if (!wb)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (wb->state != WORKBENCH_STATE_RUNNING) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_INVALID_ARG;
    }

    airy_mtx_unlock(&wb->lock);

    int exit_code = 0;
    int ret = airy_process_wait(&wb->process, timeout_ms, &exit_code);
    if (ret == AIRY_ERR_TIMEOUT)
        return cupolas_ERROR_TIMEOUT;

    wb_read_output(wb);
    airy_process_close_pipes(&wb->process);

    airy_mtx_lock(&wb->lock);
    wb_fill_status(wb, result, exit_code);
    wb->state = WORKBENCH_STATE_IDLE;
    airy_mtx_unlock(&wb->lock);

    return cupolas_OK;
}

int workbench_terminate(workbench_t *wb)
{
    if (!wb)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (wb->state != WORKBENCH_STATE_RUNNING) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_OK;
    }

    int ret = airy_process_kill(&wb->process);
    int exit_code = 0;
    airy_process_wait(&wb->process, 1000, &exit_code);

    wb_read_output(wb);
    airy_process_close_pipes(&wb->process);

    wb->state = WORKBENCH_STATE_STOPPED;
    airy_mtx_unlock(&wb->lock);

    return ret;
}

workbench_state_t workbench_get_state(workbench_t *wb)
{
    if (!wb)
        return WORKBENCH_STATE_ERROR;

    airy_mtx_lock(&wb->lock);
    workbench_state_t state = wb->state;
    airy_mtx_unlock(&wb->lock);

    return state;
}

int64_t workbench_get_pid(workbench_t *wb)
{
    if (!wb)
        return AIRY_ERR_UNKNOWN;

    airy_mtx_lock(&wb->lock);

    if (wb->state != WORKBENCH_STATE_RUNNING) {
        airy_mtx_unlock(&wb->lock);
        return AIRY_ERR_UNKNOWN;
    }

    airy_pid_t pid = wb->process.pid;
    airy_mtx_unlock(&wb->lock);

    return (int64_t)pid;
}

int workbench_write_stdin(workbench_t *wb, const void *data, size_t size,
                          size_t *written)
{
    if (!wb || !data || !written)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (wb->state != WORKBENCH_STATE_RUNNING || !wb->manager.redirect_stdin) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_INVALID_ARG;
    }

    int ret = airy_pipe_write(wb->process.stdin_fd, data, size);
    if (ret == 0)
        *written = size;

    airy_mtx_unlock(&wb->lock);
    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int workbench_read_stdout(workbench_t *wb, void *buf, size_t size,
                          size_t *read_size)
{
    if (!wb || !buf)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (!wb->manager.redirect_stdout) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_INVALID_ARG;
    }

    long n = airy_pipe_read(wb->process.stdout_fd, buf, size);
    airy_mtx_unlock(&wb->lock);

    if (n < 0)
        return cupolas_ERROR_IO;
    if (read_size)
        *read_size = (size_t)n;
    return cupolas_OK;
}

int workbench_read_stderr(workbench_t *wb, void *buf, size_t size,
                          size_t *read_size)
{
    if (!wb || !buf)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&wb->lock);

    if (!wb->manager.redirect_stderr) {
        airy_mtx_unlock(&wb->lock);
        return cupolas_ERROR_INVALID_ARG;
    }

    long n = airy_pipe_read(wb->process.stderr_fd, buf, size);
    airy_mtx_unlock(&wb->lock);

    if (n < 0)
        return cupolas_ERROR_IO;
    if (read_size)
        *read_size = (size_t)n;
    return cupolas_OK;
}

void workbench_result_free(workbench_result_t *result)
{
    if (!result)
        return;

    AIRY_FREE(result->stdout_data);
    AIRY_FREE(result->stderr_data);
    __builtin_memset(result, 0, sizeof(workbench_result_t));
}
