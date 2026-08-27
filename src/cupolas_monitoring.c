// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_monitoring.c - Monitoring Interface: Prometheus / OpenTelemetry
 */

/**
 * @file cupolas_monitoring.c
 * @brief Monitoring Interface - Prometheus / OpenTelemetry
 * @author SPHARX Ltd. - Airymax Team
 * @date 2024
 *
 * 本文件为监控模块核心域：实例生命周期管理、单例、查询接口与配置构建。
 * 系统指标采集与后台线程见 cupolas_monitoring_sys.c；
 * 指标导出见 cupolas_monitoring_export.c；
 * 健康检查与 HTTP 端点见 cupolas_monitoring_service.c。
 */

#include "cupolas_monitoring_internal.h"

#include "cupolas_metrics.h"

#include "platform/platform.h"
#include "utils/cupolas_utils.h"
#include "error.h"

#include "airy_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cupolas_monitoring_t *g_monitoring = NULL;
static cupolas_rwlock_t g_monitoring_lock = {0};

const char *monitoring_backend_string(monitoring_backend_t backend)
{
    switch (backend) {
    case MONITORING_BACKEND_PROMETHEUS:
        return "prometheus";
    case MONITORING_BACKEND_OPENTELEMETRY:
        return "opentelemetry";
    case MONITORING_BACKEND_STATSD:
        return "statsd";
    default:
        return "none";
    }
}

const char *monitoring_status_string(monitoring_status_t status)
{
    switch (status) {
    case MONITORING_STATUS_STOPPED:
        return "stopped";
    case MONITORING_STATUS_STARTING:
        return "starting";
    case MONITORING_STATUS_RUNNING:
        return "running";
    case MONITORING_STATUS_ERROR:
        return "error";
    case MONITORING_STATUS_STOPPING:
        return "stopping";
    default:
        return "unknown";
    }
}

cupolas_monitoring_t *cupolas_monitoring_create(const monitoring_config_t *manager)
{
    cupolas_monitoring_t *mgr =
        (cupolas_monitoring_t *)cupolas_mem_alloc(sizeof(cupolas_monitoring_t));
    if (!mgr) {
        return NULL;
    }

    __builtin_memset(mgr, 0, sizeof(cupolas_monitoring_t));

    if (manager) {
        AIRY_MEMCPY_SAFE(&mgr->manager, manager, sizeof(monitoring_config_t),
                         sizeof(monitoring_config_t));
    } else {
        __builtin_memset(&mgr->manager, 0, sizeof(monitoring_config_t));
        mgr->manager.backend = MONITORING_BACKEND_PROMETHEUS;
        mgr->manager.prometheus.listen_addr = "127.0.0.1";
        mgr->manager.prometheus.port = 9090;
        mgr->manager.prometheus.endpoint = "/metrics";
        mgr->manager.reporting_interval_ms = 10000;
    }

    mgr->status = MONITORING_STATUS_STOPPED;
    cupolas_rwlock_init(&mgr->lock);

    mgr->collector_running = false;
    mgr->collect_interval_ms = manager ? manager->reporting_interval_ms : 10000;
    if (mgr->collect_interval_ms < 1000)
        mgr->collect_interval_ms = 1000;

    return mgr;
}

void cupolas_monitoring_destroy(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return;

    cupolas_monitoring_stop(mgr);

    cupolas_rwlock_destroy(&mgr->lock);

    cupolas_mem_free(mgr);
}

monitoring_status_t cupolas_monitoring_get_status(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return MONITORING_STATUS_ERROR;

    cupolas_rwlock_rdlock(&mgr->lock);
    monitoring_status_t status = mgr->status;
    cupolas_rwlock_unlock(&mgr->lock);

    return status;
}

int cupolas_monitoring_report(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return AIRY_EINVAL;

    cupolas_rwlock_wrlock(&mgr->lock);

    metrics_export_prometheus(mgr->metrics_buffer, sizeof(mgr->metrics_buffer) - 1);
    mgr->metrics_buffer_size = strlen(mgr->metrics_buffer);

    mgr->last_report_time = metrics_get_timestamp_ns();

    cupolas_rwlock_unlock(&mgr->lock);

    return 0;
}

const char *cupolas_monitoring_get_listen_addr(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return NULL;

    cupolas_rwlock_rdlock(&mgr->lock);
    static char addr[128];
    snprintf(addr, sizeof(addr), "%s:%u", mgr->manager.prometheus.listen_addr,
             mgr->manager.prometheus.port);
    cupolas_rwlock_unlock(&mgr->lock);

    return addr;
}

int cupolas_monitoring_set_filter(cupolas_monitoring_t *mgr, const char **include_patterns,
                                  const char **exclude_patterns)
{
    if (!mgr)
        return AIRY_EINVAL;

    cupolas_rwlock_wrlock(&mgr->lock);

    mgr->include_count = 0;
    if (include_patterns) {
        for (size_t i = 0; include_patterns[i] && mgr->include_count < MAX_FILTER_PATTERNS; i++) {
            AIRY_STRNCPY_TERM(mgr->include_patterns[mgr->include_count], include_patterns[i],
                              MAX_PATTERN_LEN);
            mgr->include_count++;
        }
    }

    mgr->exclude_count = 0;
    if (exclude_patterns) {
        for (size_t i = 0; exclude_patterns[i] && mgr->exclude_count < MAX_FILTER_PATTERNS; i++) {
            AIRY_STRNCPY_TERM(mgr->exclude_patterns[mgr->exclude_count], exclude_patterns[i],
                              MAX_PATTERN_LEN);
            mgr->exclude_count++;
        }
    }

    cupolas_rwlock_unlock(&mgr->lock);

    return 0;
}

size_t cupolas_monitoring_get_metric_count(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return 0;

    cupolas_rwlock_rdlock(&mgr->lock);
    size_t count = metrics_get_count();
    cupolas_rwlock_unlock(&mgr->lock);

    return count;
}

uint64_t cupolas_monitoring_get_last_report_time(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return 0;

    cupolas_rwlock_rdlock(&mgr->lock);
    uint64_t time = mgr->last_report_time;
    cupolas_rwlock_unlock(&mgr->lock);

    return time;
}

const char *cupolas_monitoring_get_last_error(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return NULL;

    cupolas_rwlock_rdlock(&mgr->lock);
    const char *error = mgr->last_error[0] ? mgr->last_error : NULL;
    cupolas_rwlock_unlock(&mgr->lock);

    return error;
}

monitoring_config_t *monitoring_config_create_prometheus(uint16_t port)
{
    monitoring_config_t *manager =
        (monitoring_config_t *)cupolas_mem_alloc(sizeof(monitoring_config_t));
    if (!manager)
        return NULL;

    __builtin_memset(manager, 0, sizeof(monitoring_config_t));

    manager->backend = MONITORING_BACKEND_PROMETHEUS;
    manager->prometheus.listen_addr = "127.0.0.1";
    manager->prometheus.port = port;
    manager->prometheus.endpoint = "/metrics";
    manager->reporting_interval_ms = 10000;
    manager->buffer_size = MAX_METRICS_BUFFER;
    manager->enable_caching = true;

    return manager;
}

monitoring_config_t *monitoring_config_create_opentelemetry(const char *endpoint,
                                                            const char *service_name)
{
    monitoring_config_t *manager =
        (monitoring_config_t *)cupolas_mem_alloc(sizeof(monitoring_config_t));
    if (!manager)
        return NULL;

    __builtin_memset(manager, 0, sizeof(monitoring_config_t));

    manager->backend = MONITORING_BACKEND_OPENTELEMETRY;
    manager->opentelemetry.endpoint = endpoint;
    manager->opentelemetry.service_name = service_name;
    manager->reporting_interval_ms = 5000;
    manager->buffer_size = MAX_METRICS_BUFFER;
    manager->enable_caching = true;

    return manager;
}

void monitoring_config_destroy(monitoring_config_t *manager)
{
    cupolas_mem_free(manager);
}

cupolas_monitoring_t *cupolas_monitoring_get_instance(void)
{
    cupolas_rwlock_rdlock(&g_monitoring_lock);
    cupolas_monitoring_t *instance = g_monitoring;
    cupolas_rwlock_unlock(&g_monitoring_lock);
    return instance;
}

int cupolas_monitoring_init_instance(const monitoring_config_t *manager)
{
    cupolas_rwlock_wrlock(&g_monitoring_lock);

    if (g_monitoring) {
        cupolas_rwlock_unlock(&g_monitoring_lock);
        return 0;
    }

    g_monitoring = cupolas_monitoring_create(manager);
    if (!g_monitoring) {
        cupolas_rwlock_unlock(&g_monitoring_lock);
        return AIRY_EINVAL;
    }

    cupolas_rwlock_unlock(&g_monitoring_lock);

    return cupolas_monitoring_start(g_monitoring);
}

void cupolas_monitoring_shutdown_instance(void)
{
    cupolas_rwlock_wrlock(&g_monitoring_lock);

    if (g_monitoring) {
        cupolas_monitoring_stop(g_monitoring);
        cupolas_monitoring_destroy(g_monitoring);
        g_monitoring = NULL;
    }

    cupolas_rwlock_unlock(&g_monitoring_lock);
}
