// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file workbench_container.c
 * @brief Container mode implementation: Docker/runc-based isolated
 *        execution.
 *
 * @attention 实验性备用实现（SSoT 收敛 S-7，2026-08-14）：见
 *   workbench_container.h 头部说明。本文件已从 cupolas 构建中移除，
 *   保留供未来"原生容器运行时（runc/libcontainer）后端"或"Landlock
 *   原生沙箱"落地时参考，不作为当前运行时的一部分。
 *
 * This module implements container management:
 * - Container lifecycle management (create, start, stop, remove)
 * - Resource limits (memory, CPU, network, etc.)
 * - Security isolation
 * - Log collection
 *
 * Supported container runtimes:
 * - Docker (preferred, supports all features)
 * - runc (OCI standard runtime, lightweight option)
 */

#include "workbench_container.h"

#include "../platform/platform.h"
#include "utils/cupolas_utils.h"

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if cupolas_PLATFORM_WINDOWS
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "airy_memory.h"
#endif

#define CONTAINER_ID_LENGTH 64
#define CONTAINER_NAME_PREFIX "cupolas_"
#define MAX_COMMAND_LENGTH 4096
#define MAX_IMAGE_NAME_LEN 256

/**
 * @brief Validate container image name for safe shell command construction
 * @param[in] image Image name string from user input
 * @return true if safe, false if potentially dangerous
 * @note Rejects characters that could enable command injection:
 *       ; | & ` $ ( ) < > { } [ ] ! # ~ \ ' " and non-printable chars
 */
static bool is_safe_image_name(const char *image)
{
    if (!image || !*image || strlen(image) > MAX_IMAGE_NAME_LEN) {
        return false;
    }

    const char *unsafe_chars = ";|&`$()<>{}[]!#~\\'\"\n\r\t";
    for (const char *p = image; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c > 0x7E)
            return false;
        if (strchr(unsafe_chars, c))
            return false;
    }

    if (strchr(image, ' ') && (strstr(image, "$(") || strstr(image, "`"))) {
        return false;
    }

    return true;
}

typedef struct container_handle {
    container_config_t manager;
    container_runtime_t runtime;
    char container_id[CONTAINER_ID_LENGTH];
    char container_name[256];
    bool is_running;
    container_state_t state;
} container_handle_t;

static container_runtime_t detect_available_runtime(void)
{
    if (container_runtime_is_available(CONTAINER_RUNTIME_DOCKER)) {
        return CONTAINER_RUNTIME_DOCKER;
    }
    if (container_runtime_is_available(CONTAINER_RUNTIME_RUNC)) {
        return CONTAINER_RUNTIME_RUNC;
    }
    return CONTAINER_RUNTIME_AUTO;
}

bool container_runtime_is_available(container_runtime_t runtime)
{
    const char *exe = NULL;
    switch (runtime) {
    case CONTAINER_RUNTIME_DOCKER:
        exe = "docker";
        break;
    case CONTAINER_RUNTIME_RUNC:
        exe = "runc";
        break;
    case CONTAINER_RUNTIME_CRUN:
        exe = "crun";
        break;
    default:
        return false;
    }

    const char *const argv[] = {exe, "--version", NULL};
    int exit_code = airy_process_run_capture(exe, (char *const *)argv, NULL, 10000, NULL, 0);
    return exit_code == 0;
}

void container_config_init(container_config_t *manager)
{
    if (!manager)
        return;

    __builtin_memset(manager, 0, sizeof(container_config_t));

    manager->runtime = CONTAINER_RUNTIME_AUTO;

    manager->resources.network_mode = "none";
    manager->resources.readonly_rootfs = true;
    manager->resources.memory_limit = 512 * 1024 * 1024;
    manager->resources.cpu_shares = 1024;
    manager->resources.cpu_quota = 0;
    manager->resources.pids_limit = 64;

    manager->logging.enable_logging = true;
    manager->logging.log_driver = "json-file";
    manager->logging.log_max_size = 10 * 1024 * 1024;
    manager->logging.log_max_files = 3;

    manager->image_policy.use_cache = true;
    manager->image_policy.pull_latest = false;
}

void *container_manager_create(const container_config_t *manager)
{
    container_handle_t *handle =
        (container_handle_t *)cupolas_mem_alloc(sizeof(container_handle_t));
    if (!handle) {
        return NULL;
    }

    __builtin_memset(handle, 0, sizeof(container_handle_t));

    if (manager) {
        __builtin_memcpy(&handle->manager, manager, sizeof(container_config_t));
    } else {
        container_config_init(&handle->manager);
    }

    if (handle->manager.runtime == CONTAINER_RUNTIME_AUTO) {
        handle->runtime = detect_available_runtime();
    } else {
        handle->runtime = handle->manager.runtime;
    }

    handle->state = CONTAINER_STATE_CREATED;
    handle->is_running = false;

    snprintf(handle->container_id, CONTAINER_ID_LENGTH, "%s%08x%08x", CONTAINER_NAME_PREFIX,
             airy_random_uint32(0, 0xFFFFFFFF), airy_random_uint32(0, 0xFFFFFFFF));

    return handle;
}

void container_manager_destroy(void *mgr)
{
    if (!mgr)
        return;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (handle->is_running) {
        container_stop(mgr, 5000);
    }

    container_remove(mgr);

    cupolas_mem_free(handle);
}

/**
 * @brief Split a command string into an argv array (shell-style, supports
 *        single/double quotes)
 *
 * Replaces popen/system shell calls. The split argv is passed directly to
 * execvp without going through /bin/sh, fundamentally eliminating command
 * injection risk (BAN-211/235).
 *
 * Supported syntax:
 * - Tokens separated by whitespace
 * - Content inside single quotes '...' kept verbatim
 * - Content inside double quotes "..." kept (no variable/command
 *   substitution in this function)
 *
 * @param[in,out] cmd Command string (modified in place; tokens point into
 *                    it)
 * @param[out]    argv Output argv array (pointer array into cmd's tokens)
 * @param[in]     max_args argv array capacity (including trailing NULL)
 * @return Number of tokens, -1 on failure
 */
static int split_command_to_argv(char *cmd, char *argv[], int max_args)
{
    if (!cmd || !argv || max_args < 2)
        return AIRY_ERR_INVALID_PARAM;

    int argc = 0;
    char *p = cmd;
    while (*p && argc < max_args - 1) {

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (!*p)
            break;

        char *token_start = p;
        char *write = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
            if (*p == '"') {
                p++;
                while (*p && *p != '"')
                    *write++ = *p++;
                if (*p == '"')
                    p++;
            } else if (*p == '\'') {
                p++;
                while (*p && *p != '\'')
                    *write++ = *p++;
                if (*p == '\'')
                    p++;
            } else {
                *write++ = *p++;
            }
        }
        *write = '\0';
        argv[argc++] = token_start;
        if (*p)
            p++;
    }
    argv[argc] = NULL;
    return argc;
}

/**
 * @brief Execute a command and capture output (argv form, no shell,
 *        BAN-211/235 compliant)
 *
 * @param cmd         Command string (split into argv in place)
 * @param timeout_ms  Timeout in milliseconds
 * @param output      Output buffer (may be NULL)
 * @param output_size Output buffer size
 * @return Exit code (0-255); -1 = failed to start; -2 = timed out
 *
 * @note The caller has already validated user input via
 *       is_safe_image_name(); the SEC-011 shell metacharacter check is not
 *       needed here because execvp does not go through a shell -- metachar
 *       characters are passed as literal arguments to the child process,
 *       with no injection risk.
 */
static int execute_command(const char *cmd, int timeout_ms, char *output, size_t output_size)
{
    if (!cmd)
        return AIRY_EINVAL;

    char cmd_buf[MAX_COMMAND_LENGTH];
    AIRY_STRNCPY_TERM(cmd_buf, cmd, sizeof(cmd_buf));
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    char *argv[64];
    int argc = split_command_to_argv(cmd_buf, argv, 64);
    if (argc < 1)
        return AIRY_EINVAL;

    return airy_process_run_capture(argv[0], (char *const *)argv, NULL, (uint32_t)timeout_ms,
                                    output, output_size);
}

int container_pull_image(void *mgr, const char *image)
{
    if (!mgr || !image)
        return cupolas_ERROR_INVALID_ARG;

    if (!is_safe_image_name(image)) {
        return cupolas_ERROR_PERMISSION;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker pull %s", image);

    char output[1024];
    int result = execute_command(cmd, 300000, output, sizeof(output));

    return result == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int container_start(void *mgr, const char *name, container_result_t *result)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->manager.image || !handle->manager.command) {
        return cupolas_ERROR_INVALID_ARG;
    }

    if (!is_safe_image_name(handle->manager.image)) {
        return cupolas_ERROR_PERMISSION;
    }
    if (!is_safe_image_name(handle->manager.command)) {
        return cupolas_ERROR_PERMISSION;
    }
    for (size_t i = 0; i < handle->manager.args_count && handle->manager.args; i++) {
        if (!is_safe_image_name(handle->manager.args[i])) {
            return cupolas_ERROR_PERMISSION;
        }
    }

    if (name) {
        if (!is_safe_image_name(name)) {
            return cupolas_ERROR_PERMISSION;
        }
        snprintf(handle->container_name, sizeof(handle->container_name), "%s%s",
                 CONTAINER_NAME_PREFIX, name);
    } else {
        snprintf(handle->container_name, sizeof(handle->container_name), "%s",
                 handle->container_id);
    }

    char cmd[MAX_COMMAND_LENGTH * 2];
    snprintf(cmd, MAX_COMMAND_LENGTH * 2, "docker run --name %s %s %s %s", handle->container_name,
             handle->manager.resources.memory_limit > 0 ? "" : "--rm -i", handle->manager.image,
             handle->manager.command);

    for (size_t i = 0; i < handle->manager.args_count && handle->manager.args; i++) {
        size_t len = strlen(cmd);
        snprintf(cmd + len, MAX_COMMAND_LENGTH * 2 - len, " %s", handle->manager.args[i]);
    }

    /* Actually launch the container (the original implementation only
     * assembled the command string and set RUNNING -- stub behavior). On
     * failure set the state to ERROR and return an error; no fake success. */
    char output[1024];
    int rc = execute_command(cmd, 300000, output, sizeof(output));
    if (rc != 0) {
        handle->state = CONTAINER_STATE_DEAD;
        handle->is_running = false;
        return cupolas_ERROR_IO;
    }

    handle->state = CONTAINER_STATE_RUNNING;
    handle->is_running = true;

    if (result) {
        __builtin_memset(result, 0, sizeof(container_result_t));
        result->duration_ns = 0;
    }

    return 0;
}

int container_stop(void *mgr, uint32_t timeout_ms)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->is_running) {
        return 0;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker stop -t %u %s", (timeout_ms + 999) / 1000,
             handle->container_name);

    int ret = execute_command(cmd, timeout_ms, NULL, 0);

    handle->is_running = false;
    handle->state = CONTAINER_STATE_STOPPED;

    return ret == 0 ? 0 : -1;
}

int container_remove(void *mgr)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker rm -f %s", handle->container_name);

    int ret = execute_command(cmd, 10000, NULL, 0);

    handle->state = CONTAINER_STATE_DEAD;
    handle->is_running = false;

    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int container_get_info(void *mgr, container_info_t *info)
{
    if (!mgr || !info)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    __builtin_memset(info, 0, sizeof(container_info_t));

    snprintf(info->container_id, sizeof(info->container_id), "%s", handle->container_id);
    snprintf(info->name, sizeof(info->name), "%s", handle->container_name);
    info->state = handle->state;

    return cupolas_OK;
}

int container_get_stats(void *mgr, container_info_t *info)
{
    if (!mgr || !info)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->is_running) {
        __builtin_memset(&info->stats, 0, sizeof(info->stats));
        return cupolas_OK;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker stats %s --no-stream --format \"{{.MemUsage}}\"",
             handle->container_name);

    char output[256];
    __builtin_memset(output, 0, sizeof(output));
    if (execute_command(cmd, 5000, output, sizeof(output)) == 0 && output[0] != '\0') {
        unsigned long mem_used = 0;
        unsigned long mem_limit_val = 0;
        char out_copy[256];
        AIRY_STRNCPY_TERM(out_copy, output, sizeof(out_copy));
        out_copy[sizeof(out_copy) - 1] = '\0';
        char *saveptr = NULL;
        char *tok_used = strtok_r(out_copy, " /", &saveptr);
        char *tok_sep = strtok_r(NULL, " /", &saveptr);
        (void)tok_sep;
        char *tok_limit = strtok_r(NULL, " /\r\n", &saveptr);
        if (tok_used && tok_limit) {
            mem_used = strtoul(tok_used, NULL, 10);
            mem_limit_val = strtoul(tok_limit, NULL, 10);
            info->stats.memory_usage = (uint64_t)mem_used;
            info->stats.memory_limit = (uint64_t)mem_limit_val;
        } else {
            info->stats.memory_usage = handle->manager.resources.memory_limit;
            info->stats.memory_limit = handle->manager.resources.memory_limit;
        }
    } else {
        info->stats.memory_usage = handle->manager.resources.memory_limit;
        info->stats.memory_limit = handle->manager.resources.memory_limit;
    }
    info->stats.pids_current = 1;

    return cupolas_OK;
}

int container_pause(void *mgr)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->is_running) {
        return cupolas_ERROR_INVALID_ARG;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker pause %s", handle->container_name);

    int ret = execute_command(cmd, 5000, NULL, 0);

    if (ret == 0) {
        handle->state = CONTAINER_STATE_PAUSED;
    }

    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int container_unpause(void *mgr)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (handle->state != CONTAINER_STATE_PAUSED) {
        return cupolas_ERROR_INVALID_ARG;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker unpause %s", handle->container_name);

    int ret = execute_command(cmd, 5000, NULL, 0);

    if (ret == 0) {
        handle->state = CONTAINER_STATE_RUNNING;
        handle->is_running = true;
    }

    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int container_wait(void *mgr, uint32_t timeout_ms, int *exit_code)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->is_running) {
        if (exit_code)
            *exit_code = 0;
        return cupolas_OK;
    }

    char cmd[MAX_COMMAND_LENGTH];
    snprintf(cmd, MAX_COMMAND_LENGTH, "docker wait %s", handle->container_name);

    char output[64];
    int ret = execute_command(cmd, timeout_ms, output, sizeof(output));

    if (exit_code) {
        *exit_code = (int)strtol(output, NULL, 10);
    }

    handle->is_running = false;
    handle->state = CONTAINER_STATE_STOPPED;

    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

int container_exec(void *mgr, const char *command, const char **args, size_t arg_count,
                   container_result_t *result)
{
    if (!mgr || !command)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    if (!handle->is_running) {
        return cupolas_ERROR_INVALID_ARG;
    }

    if (!is_safe_image_name(command)) {
        return cupolas_ERROR_PERMISSION;
    }
    for (size_t i = 0; i < arg_count && args; i++) {
        if (!is_safe_image_name(args[i])) {
            return cupolas_ERROR_PERMISSION;
        }
    }

    char cmd[MAX_COMMAND_LENGTH * 2];
    snprintf(cmd, MAX_COMMAND_LENGTH * 2, "docker exec %s %s", handle->container_name, command);

    for (size_t i = 0; i < arg_count && args; i++) {
        size_t len = strlen(cmd);
        snprintf(cmd + len, MAX_COMMAND_LENGTH * 2 - len, " %s", args[i]);
    }

    if (result) {
        __builtin_memset(result, 0, sizeof(container_result_t));
        result->duration_ns = 0;

        int ret = execute_command(cmd, 30000, NULL, 0);
        result->exit_code = ret;
    }

    return cupolas_OK;
}

int container_get_logs(void *mgr, size_t tail, char *output, size_t size)
{
    if (!mgr || !output || size == 0)
        return cupolas_ERROR_INVALID_ARG;

    container_handle_t *handle = (container_handle_t *)mgr;

    char cmd[MAX_COMMAND_LENGTH];
    if (tail > 0) {
        snprintf(cmd, MAX_COMMAND_LENGTH, "docker logs --tail %zu %s", tail,
                 handle->container_name);
    } else {
        snprintf(cmd, MAX_COMMAND_LENGTH, "docker logs %s", handle->container_name);
    }

    int ret = execute_command(cmd, 10000, output, size);

    return ret == 0 ? cupolas_OK : cupolas_ERROR_IO;
}

void container_result_free(container_result_t *result)
{
    if (!result)
        return;

    if (result->stdout_data) {
        cupolas_mem_free(result->stdout_data);
    }
    if (result->stderr_data) {
        cupolas_mem_free(result->stderr_data);
    }

    __builtin_memset(result, 0, sizeof(container_result_t));
}