// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_entitlements.c
 * @brief Entitlements permission declarations implementation: fine-grained
 *        permission mechanism.
 * @details 核心职责域：上下文生命周期（load/free）、权限仲裁
 *          （fs/net/ipc/syscall/capability/vault/resource）、导出与匹配。
 *          解析域见 cupolas_entitlements_parse.c，密码学域见
 *          cupolas_entitlements_crypto.c。
 */

#include "cupolas_entitlements_internal.h"

#include "cupolas_error.h"
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "error.h"

static int ent_load_file(const char *path, cupolas_entitlements_t **entitlements)
{
    if (!path || !entitlements)
        return CUPOLAS_ENT_INVALID;

    FILE *f = fopen(path, "r");
    if (!f)
        return CUPOLAS_ENT_NOT_FOUND;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)AIRY_MALLOC(size + 1);
    if (!content) {
        fclose(f);
        return CUPOLAS_ENT_PARSE_ERROR;
    }

    size_t read_size = fread(content, 1, size, f);
    fclose(f);
    if (read_size != (size_t)size) {
        AIRY_FREE(content);
        return CUPOLAS_ENT_PARSE_ERROR;
    }
    content[read_size] = '\0';

    int result = cupolas_entitlements_load_string(content, entitlements);
    AIRY_FREE(content);

    return result;
}

int cupolas_entitlements_load(const char *yaml_path, cupolas_entitlements_t **entitlements)
{
    return ent_load_file(yaml_path, entitlements);
}

int cupolas_entitlements_load_json(const char *json_path, cupolas_entitlements_t **entitlements)
{
    return ent_load_file(json_path, entitlements);
}

int cupolas_entitlements_load_string(const char *yaml_content,
                                     cupolas_entitlements_t **entitlements)
{
    if (!yaml_content || !entitlements)
        return CUPOLAS_ENT_INVALID;

    *entitlements = (cupolas_entitlements_t *)AIRY_CALLOC(1, sizeof(cupolas_entitlements_t));
    if (!*entitlements)
        return CUPOLAS_ENT_PARSE_ERROR;

    CUPOLAS_MUTEX_INIT(&(*entitlements)->lock);

    (*entitlements)->raw_content = cupolas_strdup(yaml_content);
    (*entitlements)->load_time = cupolas_time_ms();
    (*entitlements)->is_verified = 0;

    int result = cupolas_parse_entitlements_content(yaml_content, &(*entitlements)->info);
    if (result != CUPOLAS_ENT_OK) {
        cupolas_entitlements_free(*entitlements);
        *entitlements = NULL;
        return result;
    }

    return CUPOLAS_ENT_OK;
}

void cupolas_entitlements_free(cupolas_entitlements_t *entitlements)
{
    if (!entitlements)
        return;

    AIRY_FREE(entitlements->raw_content);
    AIRY_FREE(entitlements->signature);

    AIRY_FREE(entitlements->info.agent_id);
    AIRY_FREE(entitlements->info.version);

    for (size_t i = 0; i < entitlements->info.fs_count; i++) {
        AIRY_FREE(entitlements->info.fs_permissions[i].path);
        cupolas_free_string_array(entitlements->info.fs_permissions[i].permissions,
                                  entitlements->info.fs_permissions[i].perm_count);
    }
    AIRY_FREE(entitlements->info.fs_permissions);

    for (size_t i = 0; i < entitlements->info.net_count; i++) {
        AIRY_FREE(entitlements->info.net_permissions[i].host);
        AIRY_FREE(entitlements->info.net_permissions[i].protocol);
        AIRY_FREE(entitlements->info.net_permissions[i].direction);
    }
    AIRY_FREE(entitlements->info.net_permissions);

    for (size_t i = 0; i < entitlements->info.ipc_count; i++) {
        AIRY_FREE(entitlements->info.ipc_permissions[i].target);
        cupolas_free_string_array(entitlements->info.ipc_permissions[i].permissions,
                                  entitlements->info.ipc_permissions[i].perm_count);
    }
    AIRY_FREE(entitlements->info.ipc_permissions);

    for (size_t i = 0; i < entitlements->info.vault_count; i++) {
        AIRY_FREE(entitlements->info.vault_permissions[i].cred_id);
        cupolas_free_string_array(entitlements->info.vault_permissions[i].permissions,
                                  entitlements->info.vault_permissions[i].perm_count);
    }
    AIRY_FREE(entitlements->info.vault_permissions);

    cupolas_free_string_array(entitlements->info.allowed_syscalls,
                              entitlements->info.syscall_count);
    cupolas_free_string_array(entitlements->info.allowed_capabilities,
                              entitlements->info.cap_count);

    cupolas_mutex_destroy(&entitlements->lock);

    AIRY_FREE(entitlements);
}

int cupolas_entitlements_check_fs(cupolas_entitlements_t *entitlements, const char *path,
                                  const char *operation)
{
    if (!entitlements_verified_valid(entitlements) || !path || !operation)
        return 0;

    for (size_t i = 0; i < entitlements->info.fs_count; i++) {
        cupolas_ent_fs_permission_t *perm = &entitlements->info.fs_permissions[i];

        if (cupolas_entitlements_match_path(perm->path, path)) {
            for (size_t j = 0; j < perm->perm_count; j++) {
                if (strcmp(perm->permissions[j], operation) == 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

int cupolas_entitlements_check_net(cupolas_entitlements_t *entitlements, const char *host,
                                   uint16_t port, const char *protocol, const char *direction)
{
    if (!entitlements_verified_valid(entitlements) || !host)
        return 0;

    for (size_t i = 0; i < entitlements->info.net_count; i++) {
        cupolas_ent_net_permission_t *perm = &entitlements->info.net_permissions[i];

        int host_match = cupolas_entitlements_match_host(perm->host, host);
        int port_match = (perm->port == 0 || perm->port == port);
        int proto_match = !perm->protocol || strcmp(perm->protocol, protocol) == 0;
        int dir_match = !perm->direction || strcmp(perm->direction, direction) == 0 ||
                        strcmp(perm->direction, "both") == 0;

        if (host_match && port_match && proto_match && dir_match) {
            return 1;
        }
    }

    return 0;
}

int cupolas_entitlements_check_ipc(cupolas_entitlements_t *entitlements, const char *target,
                                   const char *operation)
{
    if (!entitlements || !target || !operation)
        return 0;

    for (size_t i = 0; i < entitlements->info.ipc_count; i++) {
        cupolas_ent_ipc_permission_t *perm = &entitlements->info.ipc_permissions[i];

        if (strcmp(perm->target, target) == 0) {
            for (size_t j = 0; j < perm->perm_count; j++) {
                if (strcmp(perm->permissions[j], operation) == 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

int cupolas_entitlements_check_syscall(cupolas_entitlements_t *entitlements,
                                       const char *syscall_name)
{
    if (!entitlements || !syscall_name)
        return 0;

    for (size_t i = 0; i < entitlements->info.syscall_count; i++) {
        if (strcmp(entitlements->info.allowed_syscalls[i], syscall_name) == 0) {
            return 1;
        }
    }

    return 0;
}

int cupolas_entitlements_check_capability(cupolas_entitlements_t *entitlements,
                                          const char *capability)
{
    if (!entitlements || !capability)
        return 0;

    for (size_t i = 0; i < entitlements->info.cap_count; i++) {
        if (strcmp(entitlements->info.allowed_capabilities[i], capability) == 0) {
            return 1;
        }
    }

    return 0;
}

int cupolas_entitlements_check_vault(cupolas_entitlements_t *entitlements, const char *cred_id,
                                     const char *operation)
{
    if (!entitlements_verified_valid(entitlements) || !cred_id || !operation)
        return 0;

    for (size_t i = 0; i < entitlements->info.vault_count; i++) {
        cupolas_ent_vault_permission_t *perm = &entitlements->info.vault_permissions[i];

        if (strcmp(perm->cred_id, cred_id) == 0) {
            for (size_t j = 0; j < perm->perm_count; j++) {
                if (strcmp(perm->permissions[j], operation) == 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

int cupolas_entitlements_get_resource_limits(cupolas_entitlements_t *entitlements,
                                             cupolas_ent_resource_limits_t *limits)
{
    if (!entitlements || !limits)
        return CUPOLAS_ENT_INVALID;

    *limits = entitlements->info.resources;
    return CUPOLAS_ENT_OK;
}

int cupolas_entitlements_check_resource(cupolas_entitlements_t *entitlements,
                                        const char *resource_type, uint64_t current_value)
{
    if (!entitlements || !resource_type)
        return 0;

    cupolas_ent_resource_limits_t *limits = &entitlements->info.resources;

    if (strcmp(resource_type, "cpu") == 0) {
        return current_value <= limits->max_cpu_percent;
    } else if (strcmp(resource_type, "memory") == 0) {
        return current_value <= limits->max_memory_bytes;
    } else if (strcmp(resource_type, "disk") == 0) {
        return current_value <= limits->max_disk_bytes;
    } else if (strcmp(resource_type, "process") == 0) {
        return current_value <= limits->max_processes;
    } else if (strcmp(resource_type, "thread") == 0) {
        return current_value <= limits->max_threads;
    } else if (strcmp(resource_type, "file") == 0) {
        return current_value <= limits->max_open_files;
    } else if (strcmp(resource_type, "connection") == 0) {
        return current_value <= limits->max_network_connections;
    }

    return 0;
}

int cupolas_entitlements_get_info(cupolas_entitlements_t *entitlements,
                                  cupolas_entitlements_info_t *info)
{
    if (!entitlements || !info)
        return CUPOLAS_ENT_INVALID;

    *info = entitlements->info;
    return CUPOLAS_ENT_OK;
}

const char *cupolas_entitlements_get_agent_id(cupolas_entitlements_t *entitlements)
{
    if (!entitlements)
        return NULL;
    return entitlements->info.agent_id;
}

int cupolas_entitlements_check_validity(cupolas_entitlements_t *entitlements)
{
    if (!entitlements)
        return CUPOLAS_ENT_INVALID;

    uint64_t now = cupolas_time_ms() / 1000;

    if (entitlements->info.not_before > 0 && now < entitlements->info.not_before) {
        return CUPOLAS_ENT_EXPIRED;
    }

    if (entitlements->info.not_after > 0 && now > entitlements->info.not_after) {
        return CUPOLAS_ENT_EXPIRED;
    }

    return CUPOLAS_ENT_OK;
}

typedef struct {
    const char *agent_id;
    const char *version;
    unsigned long long not_before;
    unsigned long long not_after;
    unsigned int max_cpu;
    unsigned long long max_mem;
    unsigned long long max_disk;
    unsigned int max_proc;
    unsigned int max_threads;
    unsigned int max_files;
    unsigned int max_conns;
} ent_fields_t;

static void ent_fill(const cupolas_entitlements_t *e, ent_fields_t *f)
{
    f->agent_id = e->info.agent_id ? e->info.agent_id : "";
    f->version = e->info.version ? e->info.version : "";
    f->not_before = (unsigned long long)e->info.not_before;
    f->not_after = (unsigned long long)e->info.not_after;
    f->max_cpu = e->info.resources.max_cpu_percent;
    f->max_mem = (unsigned long long)e->info.resources.max_memory_bytes;
    f->max_disk = (unsigned long long)e->info.resources.max_disk_bytes;
    f->max_proc = e->info.resources.max_processes;
    f->max_threads = e->info.resources.max_threads;
    f->max_files = e->info.resources.max_open_files;
    f->max_conns = e->info.resources.max_network_connections;
}

static int ent_write(const ent_fields_t *f, char *out, size_t cap, int json)
{
    if (json)
        return snprintf(out, cap, "{\n  \"agent_id\": \"%s\",\n  \"version\": \"%s\",\n"
                        "  \"not_before\": %llu,\n  \"not_after\": %llu,\n"
                        "  \"resources\": {\n    \"max_cpu_percent\": %u,\n"
                        "    \"max_memory_bytes\": %llu,\n    \"max_disk_bytes\": %llu,\n"
                        "    \"max_processes\": %u,\n    \"max_threads\": %u,\n"
                        "    \"max_open_files\": %u,\n"
                        "    \"max_network_connections\": %u\n  }\n}\n",
                        f->agent_id, f->version, f->not_before, f->not_after, f->max_cpu,
                        f->max_mem, f->max_disk, f->max_proc, f->max_threads, f->max_files,
                        f->max_conns);

    return snprintf(out, cap, "agent_id: %s\nversion: %s\nnot_before: %llu\nnot_after: %llu\n"
                    "resources:\n  max_cpu_percent: %u\n  max_memory_bytes: %llu\n"
                    "  max_disk_bytes: %llu\n  max_processes: %u\n  max_threads: %u\n"
                    "  max_open_files: %u\n  max_network_connections: %u\n",
                    f->agent_id, f->version, f->not_before, f->not_after, f->max_cpu,
                    f->max_mem, f->max_disk, f->max_proc, f->max_threads, f->max_files,
                    f->max_conns);
}

static int ent_export(cupolas_entitlements_t *e, char *out, size_t *len, int json)
{
    if (!e || !out || !len)
        return CUPOLAS_ENT_INVALID;

    ent_fields_t f;
    ent_fill(e, &f);

    int written = ent_write(&f, out, *len, json);

    if (written < 0 || (size_t)written >= *len) {
        *len = (size_t)written + 1;
        return CUPOLAS_ENT_PARSE_ERROR;
    }

    *len = (size_t)written;
    return CUPOLAS_ENT_OK;
}

int cupolas_entitlements_export_yaml(cupolas_entitlements_t *entitlements, char *yaml_out,
                                     size_t *len)
{
    return ent_export(entitlements, yaml_out, len, 0);
}

int cupolas_entitlements_export_json(cupolas_entitlements_t *entitlements, char *json_out,
                                     size_t *len)
{
    return ent_export(entitlements, json_out, len, 1);
}

const char *cupolas_entitlements_result_string(cupolas_ent_result_t result)
{
    switch (result) {
    case CUPOLAS_ENT_OK:
        return "Success";
    case CUPOLAS_ENT_INVALID:
        return "Invalid parameter";
    case CUPOLAS_ENT_SIGNATURE_INVALID:
        return "Invalid signature";
    case CUPOLAS_ENT_EXPIRED:
        return "Expired";
    case CUPOLAS_ENT_DENIED:
        return "Permission denied";
    case CUPOLAS_ENT_NOT_FOUND:
        return "Not found";
    case CUPOLAS_ENT_PARSE_ERROR:
        return "Parse error";
    default:
        return "Unknown error";
    }
}

int cupolas_entitlements_match_path(const char *pattern, const char *path)
{
    if (!pattern || !path)
        return 0;

    while (*pattern && *path) {
        if (*pattern == '*') {
            pattern++;
            if (*pattern == '\0')
                return 1;

            while (*path) {
                if (cupolas_entitlements_match_path(pattern, path))
                    return 1;
                path++;
            }
            return 0;
        } else if (*pattern == '?') {
            pattern++;
            path++;
        } else if (*pattern == *path) {
            pattern++;
            path++;
        } else {
            return 0;
        }
    }

    while (*pattern == '*')
        pattern++;

    return *pattern == '\0' && *path == '\0';
}

int cupolas_entitlements_match_host(const char *pattern, const char *host)
{
    return cupolas_host_match(pattern, host);
}
