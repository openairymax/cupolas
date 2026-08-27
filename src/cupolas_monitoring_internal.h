/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * cupolas_monitoring_internal.h - Monitoring 模块内部共享定义
 */

/**
 * @file cupolas_monitoring_internal.h
 * @brief 监控模块内部共享定义（拆分自 cupolas_monitoring.c）
 *
 * 供拆分后的多个 .c 文件共享：
 * - 实例结构体与内部宏
 * - 健康检查条目类型
 */

#ifndef CUPOLAS_MONITORING_INTERNAL_H
#define CUPOLAS_MONITORING_INTERNAL_H

#include "cupolas_monitoring.h"

#include "platform/platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_METRICS_BUFFER (64 * 1024)
#define MAX_HEALTH_CHECKS 32

#define MAX_FILTER_PATTERNS 16
#define MAX_PATTERN_LEN 128
#define HTTP_RESPONSE_BUF (256 * 1024)

typedef struct health_check_entry {
    char name[128];
    health_check_fn_t callback;
    bool registered;
} health_check_entry_t;

struct cupolas_monitoring {
    monitoring_config_t manager;
    monitoring_status_t status;

    cupolas_rwlock_t lock;

    char metrics_buffer[MAX_METRICS_BUFFER];
    size_t metrics_buffer_size;

    health_check_entry_t health_checks[MAX_HEALTH_CHECKS];
    size_t health_check_count;

    char include_patterns[MAX_FILTER_PATTERNS][MAX_PATTERN_LEN];
    size_t include_count;
    char exclude_patterns[MAX_FILTER_PATTERNS][MAX_PATTERN_LEN];
    size_t exclude_count;

    cupolas_thread_t reporter_thread;
    bool reporter_running;

    cupolas_thread_t collector_thread;
    bool collector_running;
    uint32_t collect_interval_ms;

    uint64_t last_report_time;
    char last_error[512];

    cupolas_monitoring_t *instance;
};

#endif /* CUPOLAS_MONITORING_INTERNAL_H */
