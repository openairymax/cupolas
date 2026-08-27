// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_monitoring_export.c - Monitoring 指标导出（Prometheus / OTLP）
 */

/**
 * @file cupolas_monitoring_export.c
 * @brief 监控模块指标导出域
 *
 * 本文件拆分自 cupolas_monitoring.c，负责：
 * - Prometheus 文本格式导出（拉取模式）
 * - OpenTelemetry OTLP JSON 格式导出（推送模式）
 */

#include "cupolas_monitoring_internal.h"

#include "cupolas_metrics.h"

#include "platform/platform.h"

#include "airy_memory.h"

#include <stdio.h>
#include <string.h>

size_t cupolas_monitoring_export(cupolas_monitoring_t *mgr, char *buffer, size_t size)
{
    if (!mgr || !buffer || size == 0)
        return 0;

    cupolas_rwlock_rdlock(&mgr->lock);

    size_t copied = 0;
    if (mgr->metrics_buffer_size > 0 && size > mgr->metrics_buffer_size) {
        AIRY_MEMCPY_SAFE(buffer, mgr->metrics_buffer, mgr->metrics_buffer_size, size);
        copied = mgr->metrics_buffer_size;
    }

    cupolas_rwlock_unlock(&mgr->lock);

    return copied;
}

/**
 * @brief Export metrics in OpenTelemetry OTLP JSON format
 * @param[in] mgr Monitoring manager handle
 * @param[out] buffer Output buffer for OTLP JSON format metrics
 * @param[in] size Size of output buffer in bytes
 * @return Number of bytes written to buffer, or 0 on error
 * @note Thread-safe: Safe to call from multiple threads concurrently
 * @reentrant Yes
 * @ownership buffer: caller provides buffer, function writes to it
 *
 * @details
 * Generates OpenTelemetry Protocol (OTLP) JSON export format:
 *
 * {
 *   "resourceMetrics": [{
 *     "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "cupolas"}}]},
 *     "scopeMetrics": [{
 *       "scope": {"name": "cupolas.monitoring"},
 *       "metrics": [
 *         {"name": "cupolas_permission_checks_total", "description": "...", "unit": "1",
 *          "sum": {"dataPoints": [{"attributes": [...], "asInt": 1234}]}}
 *       ]
 *     }]
 *   }],
 *   "timestamp_ns": 1704067200000000000
 * }
 */
size_t cupolas_monitoring_export_otlp(cupolas_monitoring_t *mgr, char *buffer, size_t size)
{
    if (!mgr || !buffer || size == 0) {
        return 0;
    }

    cupolas_rwlock_rdlock(&mgr->lock);

    if (mgr->metrics_buffer_size == 0) {
        cupolas_rwlock_unlock(&mgr->lock);
        return 0;
    }

    size_t written = 0;
    written +=
        snprintf(buffer + written, size - written,
                 "{\n"
                 "  \"resourceMetrics\": [{\n"
                 "    \"resource\": {\n"
                 "      \"attributes\": [\n"
                 "        {\"key\": \"service.name\", \"value\": {\"stringValue\": \"%s\"}}\n"
                 "      ]\n"
                 "    },\n"
                 "    \"scopeMetrics\": [{\n"
                 "      \"scope\": {\"name\": \"cupolas.monitoring\"},\n"
                 "      \"metrics\": [\n",
                 mgr->manager.opentelemetry.service_name ? mgr->manager.opentelemetry.service_name :
                                                           "cupolas");

    if (written >= size) {
        cupolas_rwlock_unlock(&mgr->lock);
        return 0;
    }

    bool first_metric = true;
    const char *metric_data = mgr->metrics_buffer;
    const char *line_start = metric_data;
    int line_num = 0;

    while (*metric_data && written < size) {
        if (*metric_data == '\n' || *(metric_data + 1) == '\0') {
            size_t line_len = (size_t)(metric_data - line_start);
            if (line_len > 0 && line_len < 256) {
                char line[256];
                AIRY_STRNCPY_TERM(line, line_start, sizeof(line));

                if (strncmp(line, "# HELP ", 7) == 0 || strncmp(line, "# TYPE ", 7) == 0) {
                    line_start = metric_data + 1;
                    metric_data++;
                    line_num++;
                    continue;
                }

                if (line[0] != '#' && line[0] != '\0' && strchr(line, ' ') != NULL) {
                    char metric_name[128] = {0};
                    char metric_value[64] = {0};

                    char *space_pos = strrchr(line, ' ');
                    if (space_pos) {
                        size_t name_len = (size_t)(space_pos - line);
                        if (name_len < sizeof(metric_name)) {
                            AIRY_STRNCPY_TERM(metric_name, line, sizeof(metric_name));
                            AIRY_STRNCPY_TERM(metric_value, space_pos + 1, sizeof(metric_value));

                            if (!first_metric) {
                                written += snprintf(buffer + written, size - written, ",\n");
                            }
                            first_metric = false;

                            written += snprintf(
                                buffer + written, size - written,
                                "        {\n"
                                "          \"name\": \"%s\",\n"
                                "          \"description\": \"%s metric exported from cupolas\",\n"
                                "          \"unit\": \"1\",\n"
                                "          \"sum\": {\n"
                                "            \"isMonotonic\": true,\n"
                                "            \"aggregationTemporality\": 2,\n"
                                "            \"dataPoints\": [{\n"
                                "              \"timeUnixNano\": %llu,\n"
                                "              \"asInt\": %s\n"
                                "            }]\n"
                                "          }\n"
                                "        }",
                                metric_name, metric_name, (unsigned long long)mgr->last_report_time,
                                metric_value);

                            if (written >= size) {
                                cupolas_rwlock_unlock(&mgr->lock);
                                return 0;
                            }
                        }
                    }
                }
            }
            line_start = metric_data + 1;
        }
        metric_data++;
    }

    written += snprintf(buffer + written, size - written,
                        "\n      ]\n"
                        "    }]\n"
                        "  }],\n"
                        "  \"timestamp_ns\": %llu\n"
                        "}\n",
                        (unsigned long long)mgr->last_report_time);

    cupolas_rwlock_unlock(&mgr->lock);

    return (written < size) ? written : 0;
}
