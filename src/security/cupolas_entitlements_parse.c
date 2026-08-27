// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_entitlements_parse.c
 * @brief Entitlements YAML/JSON content parsing domain.
 * @details 从 cupolas_entitlements.c 拆出的解析职责域：YAML 行解析、字符串
 *          数组解析与字段处理器注册表（key → handler）。输出写入
 *          cupolas_entitlements_info_t，不接触完整上下文。
 */

#include "cupolas_entitlements_internal.h"

#include "cupolas_error.h"
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *cupolas_str_trim(char *str)
{
    if (!str)
        return NULL;
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
        str++;
    if (*str == 0)
        return str;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        end--;
    *(end + 1) = '\0';
    return str;
}

void cupolas_free_string_array(char **arr, size_t count)
{
    if (!arr)
        return;
    for (size_t i = 0; i < count; i++) {
        AIRY_FREE(arr[i]);
    }
    AIRY_FREE(arr);
}

static char **cupolas_parse_string_array(const char *content, size_t *count)
{
    char **arr = NULL;
    *count = 0;
    if (!content)
        return NULL;

    size_t capacity = 16;
    SAFE_MALLOC_ARRAY(arr, capacity, sizeof(char *));
    if (!arr)
        return NULL;

    char *dup = cupolas_strdup(content);
    if (!dup) {
        AIRY_FREE(arr);
        return NULL;
    }

    char *saveptr;
    char *token = strtok_r(dup, ",\n", &saveptr);
    while (token) {
        token = cupolas_str_trim(token);
        /* Strip YAML inline-array syntax `[read, write]`: the first token
         * starts with `[` and the last ends with `]` (after strtok splits
         * on commas, the brackets land on the first/last tokens). */
        size_t tok_len = strlen(token);
        if (tok_len > 0 && token[0] == '[') {
            token++;
            tok_len--;
        }
        if (tok_len > 0 && token[tok_len - 1] == ']') {
            token[tok_len - 1] = '\0';
        }
        token = cupolas_str_trim(token);
        if (*token != '\0') {
            if (*count >= capacity) {
                capacity *= 2;
                char **new_arr = (char **)AIRY_REALLOC(arr, capacity * sizeof(char *));
                if (!new_arr) {
                    AIRY_FREE(dup);
                    cupolas_free_string_array(arr, *count);
                    return NULL;
                }
                arr = new_arr;
            }
            arr[*count] = cupolas_strdup(token);
            if (arr[*count])
                (*count)++;
        }
        token = strtok_r(NULL, ",\n", &saveptr);
    }

    AIRY_FREE(dup);
    return arr;
}

static int cupolas_parse_yaml_line(const char *line, char **key, char **value, int *indent)
{
    *key = NULL;
    *value = NULL;
    *indent = 0;

    const char *p = line;
    while (*p == ' ') {
        (*indent)++;
        p++;
    }

    const char *colon = strchr(p, ':');
    if (!colon)
        return AIRY_EINVAL;

    size_t key_len = colon - p;
    *key = (char *)AIRY_MALLOC(key_len + 1);
    if (!*key)
        return AIRY_EINVAL;
    __builtin_memcpy(*key, p, key_len);
    (*key)[key_len] = '\0';
    *key = cupolas_str_trim(*key);

    const char *v = colon + 1;
    while (*v == ' ')
        v++;

    if (*v != '\0' && *v != '\n' && *v != '\r') {
        size_t value_len = strlen(v);
        while (value_len > 0 &&
               (v[value_len - 1] == '\n' || v[value_len - 1] == '\r' || v[value_len - 1] == ' ')) {
            value_len--;
        }
        *value = (char *)AIRY_MALLOC(value_len + 1);
        if (!*value) {
            AIRY_FREE(*key);
            *key = NULL;
            return AIRY_EINVAL;
        }
        __builtin_memcpy(*value, v, value_len);
        (*value)[value_len] = '\0';
    }

    return 0;
}

static void handle_agent_id(cupolas_entitlements_info_t *info, const char *value)
{
    info->agent_id = cupolas_strdup(value);
}

static void handle_version(cupolas_entitlements_info_t *info, const char *value)
{
    info->version = cupolas_strdup(value);
}

static void handle_not_before(cupolas_entitlements_info_t *info, const char *value)
{
    info->not_before = strtoull(value, NULL, 10);
}

static void handle_not_after(cupolas_entitlements_info_t *info, const char *value)
{
    info->not_after = strtoull(value, NULL, 10);
}

static void handle_max_cpu_percent(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_cpu_percent = (uint32_t)strtoul(value, NULL, 10);
}

static void handle_max_memory_bytes(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_memory_bytes = strtoull(value, NULL, 10);
}

static void handle_max_disk_bytes(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_disk_bytes = strtoull(value, NULL, 10);
}

static void handle_max_processes(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_processes = (uint32_t)strtoul(value, NULL, 10);
}

static void handle_max_threads(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_threads = (uint32_t)strtoul(value, NULL, 10);
}

static void handle_max_open_files(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_open_files = (uint32_t)strtoul(value, NULL, 10);
}

static void handle_max_network_connections(cupolas_entitlements_info_t *info, const char *value)
{
    info->resources.max_network_connections = (uint32_t)strtoul(value, NULL, 10);
}

static void handle_allowed_syscalls(cupolas_entitlements_info_t *info, const char *value)
{
    info->allowed_syscalls = cupolas_parse_string_array(value, &info->syscall_count);
}

static void handle_allowed_capabilities(cupolas_entitlements_info_t *info, const char *value)
{
    info->allowed_capabilities = cupolas_parse_string_array(value, &info->cap_count);
}

typedef struct {
    const char *key;
    void (*handler)(cupolas_entitlements_info_t *, const char *);
} key_handler_map_t;

static const key_handler_map_t g_key_handlers[] = {
    {"agent_id", handle_agent_id},
    {"version", handle_version},
    {"not_before", handle_not_before},
    {"not_after", handle_not_after},
    {"max_cpu_percent", handle_max_cpu_percent},
    {"max_memory_bytes", handle_max_memory_bytes},
    {"max_disk_bytes", handle_max_disk_bytes},
    {"max_processes", handle_max_processes},
    {"max_threads", handle_max_threads},
    {"max_open_files", handle_max_open_files},
    {"max_network_connections", handle_max_network_connections},
    {"allowed_syscalls", handle_allowed_syscalls},
    {"allowed_capabilities", handle_allowed_capabilities},
};

static const size_t g_key_handlers_count = sizeof(g_key_handlers) / sizeof(g_key_handlers[0]);

int cupolas_parse_entitlements_content(const char *content,
                                       cupolas_entitlements_info_t *info)
{
    __builtin_memset(info, 0, sizeof(*info));

    char *dup = cupolas_strdup(content);
    if (!dup)
        return CUPOLAS_ENT_PARSE_ERROR;

    char *saveptr;
    char *line = strtok_r(dup, "\n", &saveptr);

    while (line) {
        char *key = NULL;
        char *value = NULL;
        int indent = 0;

        if (cupolas_parse_yaml_line(line, &key, &value, &indent) == 0 && key && value) {
            for (size_t i = 0; i < g_key_handlers_count; i++) {
                if (strcmp(key, g_key_handlers[i].key) == 0) {
                    g_key_handlers[i].handler(info, value);
                    break;
                }
            }
        }

        AIRY_FREE(key);
        AIRY_FREE(value);
        line = strtok_r(NULL, "\n", &saveptr);
    }

    AIRY_FREE(dup);
    return CUPOLAS_ENT_OK;
}
