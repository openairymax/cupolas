// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_monitoring_service.c - Monitoring 健康检查与 HTTP 端点
 */

/**
 * @file cupolas_monitoring_service.c
 * @brief 监控模块服务域：健康检查与动态 HTTP 端点
 *
 * 本文件拆分自 cupolas_monitoring.c，负责：
 * - 健康检查注册与执行
 * - /metrics、/health、/monitoring 端点处理（经由 gateway 注册回调）
 */

#include "cupolas_monitoring_internal.h"

#include "cupolas_metrics.h"

#include "platform/platform.h"
#include "utils/cupolas_utils.h"
#include "error.h"

#include "airy_memory.h"

#include <stdio.h>
#include <string.h>

/* ========== Dynamic Endpoint Handlers (via gateway registration) ========== */
static int handle_metrics_endpoint(const cupolas_endpoint_request_t *req,
                                   cupolas_endpoint_response_t *resp)
{
    cupolas_monitoring_t *mgr = (cupolas_monitoring_t *)req->user_data;

    cupolas_rwlock_rdlock(&mgr->lock);

    char buf[HTTP_RESPONSE_BUF];
    size_t len = metrics_export_prometheus(buf, sizeof(buf));

    cupolas_rwlock_unlock(&mgr->lock);

    if (len > 0) {
        resp->status_code = 200;
        resp->content_type = "text/plain; version=0.1.1; charset=utf-8";
        resp->body = AIRY_STRNDUP(buf, len);
        resp->body_len = len;
    } else {
        const char *no_metrics = "# No metrics available\n";
        resp->status_code = 200;
        resp->content_type = "text/plain; version=0.1.1; charset=utf-8";
        resp->body = AIRY_STRDUP(no_metrics);
        resp->body_len = strlen(no_metrics);
    }

    return 0;
}

static int handle_health_endpoint(const cupolas_endpoint_request_t *req,
                                  cupolas_endpoint_response_t *resp)
{
    cupolas_monitoring_t *mgr = (cupolas_monitoring_t *)req->user_data;

    health_check_result_t results[MAX_HEALTH_CHECKS];
    int count = cupolas_monitoring_check_health(mgr, results, MAX_HEALTH_CHECKS);

    char buf[4096];
    size_t off = snprintf(buf, sizeof(buf), "{\n");
    bool all_healthy = true;

    for (int i = 0; i < count && off < sizeof(buf) - 256; i++) {
        off += snprintf(buf + off, sizeof(buf) - off, "  \"%s\": %s,\n",
                        results[i].component ? results[i].component : "unknown",
                        results[i].healthy ? "true" : "false");
        if (!results[i].healthy)
            all_healthy = false;
    }

    off += snprintf(buf + off, sizeof(buf) - off, "  \"status\": \"%s\"\n}\n",
                    all_healthy ? "healthy" : "unhealthy");

    resp->status_code = all_healthy ? 200 : 503;
    resp->content_type = "application/json";
    resp->body = AIRY_STRNDUP(buf, off);
    resp->body_len = off;

    return 0;
}

static int handle_index_endpoint(const cupolas_endpoint_request_t *req __attribute__((unused)),
                                 cupolas_endpoint_response_t *resp)
{
    const char *body = "<html><head><title>Cupolas Monitoring</title></head><body>"
                       "<h2>AgentRT Cupolas Monitoring</h2>"
                       "<ul>"
                       "<li><a href=\"/metrics\">/metrics</a> - Prometheus exposition format</li>"
                       "<li><a href=\"/health\">/health</a> - Health check endpoint</li>"
                       "</ul></body></html>";
    resp->status_code = 200;
    resp->content_type = "text/html";
    resp->body = AIRY_STRDUP(body);
    resp->body_len = strlen(body);

    return 0;
}

int cupolas_monitoring_register_health_check(cupolas_monitoring_t *mgr, const char *name,
                                             health_check_fn_t callback)
{
    if (!mgr || !name || !callback)
        return AIRY_EINVAL;

    cupolas_rwlock_wrlock(&mgr->lock);

    if (mgr->health_check_count >= MAX_HEALTH_CHECKS) {
        cupolas_rwlock_unlock(&mgr->lock);
        return AIRY_EINVAL;
    }

    health_check_entry_t *entry = &mgr->health_checks[mgr->health_check_count++];
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    entry->callback = callback;
    entry->registered = true;

    cupolas_rwlock_unlock(&mgr->lock);

    return 0;
}

int cupolas_monitoring_check_health(cupolas_monitoring_t *mgr, health_check_result_t *results,
                                    size_t max_results)
{
    if (!mgr || !results || max_results == 0)
        return 0;

    cupolas_rwlock_rdlock(&mgr->lock);

    size_t count = 0;
    for (size_t i = 0; i < mgr->health_check_count && count < max_results; i++) {
        health_check_entry_t *entry = &mgr->health_checks[i];
        if (entry->registered && entry->callback) {
            results[count].timestamp_ns = metrics_get_timestamp_ns();
            results[count].healthy = entry->callback();
            results[count].component = entry->name;
            results[count].message = results[count].healthy ? "OK" : "FAILED";
            count++;
        }
    }

    cupolas_rwlock_unlock(&mgr->lock);

    return (int)count;
}

int cupolas_monitoring_register_endpoints(cupolas_monitoring_t *mgr, void *server_handle,
                                          cupolas_endpoint_register_fn_t register_fn)
{
    if (!mgr || !server_handle || !register_fn)
        return AIRY_EINVAL;

    airy_err_t err;

    err = register_fn(server_handle, "GET", "/metrics", handle_metrics_endpoint, mgr);
    if (err != AIRY_SUCCESS) {
        CUPOLAS_LOG_ERROR("monitoring: failed to register /metrics endpoint");
        return AIRY_EINVAL;
    }

    err = register_fn(server_handle, "GET", "/health", handle_health_endpoint, mgr);
    if (err != AIRY_SUCCESS) {
        CUPOLAS_LOG_ERROR("monitoring: failed to register /health endpoint");
        return AIRY_EINVAL;
    }

    err = register_fn(server_handle, "GET", "/monitoring", handle_index_endpoint, mgr);
    if (err != AIRY_SUCCESS) {
        CUPOLAS_LOG_ERROR("monitoring: failed to register /monitoring endpoint");
        return AIRY_EINVAL;
    }

    CUPOLAS_LOG("monitoring: endpoints registered via callback");

    return 0;
}
