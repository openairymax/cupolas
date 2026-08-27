// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_monitoring_sys.c - Monitoring 系统指标采集与后台线程
 */

/**
 * @file cupolas_monitoring_sys.c
 * @brief 监控模块系统指标采集域
 *
 * 本文件拆分自 cupolas_monitoring.c，负责：
 * - 进程系统指标采集（RSS / CPU / 线程数，按平台实现）
 * - 指标采集线程与上报线程
 * - 监控启停（线程生命周期管理）
 */

#include "cupolas_monitoring_internal.h"

#include "cupolas_metrics.h"

#include "platform/platform.h"
#include "utils/cupolas_utils.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if cupolas_PLATFORM_WINDOWS
#include <psapi.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/* ========== System Metrics Collection (Linux /proc) ========== */
#if cupolas_PLATFORM_POSIX
#include <sys/resource.h>
#include "airy_memory.h"

static uint64_t get_process_rss_bytes(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return 0;
    char line[256];
    uint64_t rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            unsigned long kb = 0;
            char *endptr = NULL;
            kb = strtoul(line + 6, &endptr, 10);
            if (endptr != line + 6)
                rss = kb * 1024UL;
            break;
        }
    }
    fclose(f);
    return rss;
}

static double get_process_cpu_seconds(void)
{
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f)
        return 0.0;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0.0;
    }
    fclose(f);

    long utime = 0, stime = 0;
    int field = 0;
    const char *p = line;
    while (*p && field < 15) {
        if (*p == ' ')
            field++;
        else if (field == 13)
            utime = strtol(p, NULL, 10);
        else if (field == 14)
            stime = strtol(p, NULL, 10);
        p++;
    }
    static long clk_tck = 0;
    if (clk_tck == 0)
        clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0)
        clk_tck = 100;
    return (double)(utime + stime) / (double)clk_tck;
}

static int get_thread_count(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return 1;
    char line[256];
    int threads = 1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Threads:", 8) == 0) {
            threads = (int)strtol(line + 8, NULL, 10);
            break;
        }
    }
    fclose(f);
    return threads;
}

#else

#if cupolas_PLATFORM_WINDOWS
static uint64_t get_process_rss_bytes(void)
{
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

static double get_process_cpu_seconds(void)
{
    FILETIME creation, exit, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        ULARGE_INTEGER kt, ut;
        kt.LowPart = kernel.dwLowDateTime;
        kt.HighPart = kernel.dwHighDateTime;
        ut.LowPart = user.dwLowDateTime;
        ut.HighPart = user.dwHighDateTime;
        return (double)(kt.QuadPart + ut.QuadPart) / 10000000.0;
    }
    return 0.0;
}

static int get_thread_count(void)
{
    return 1;
}
#else
static uint64_t get_process_rss_bytes(void)
{
    return 0;
}

static double get_process_cpu_seconds(void)
{
    return 0.0;
}

static int get_thread_count(void)
{
    return 1;
}
#endif

#endif

static void *collector_thread_func(void *arg)
{
    cupolas_monitoring_t *mgr = (cupolas_monitoring_t *)arg;

    while (mgr->collector_running) {
        metrics_gauge_set(METRIC_PROCESS_MEMORY_BYTES, NULL, (double)get_process_rss_bytes());
        metrics_gauge_set(METRIC_PROCESS_CPU_SECONDS, NULL, get_process_cpu_seconds());
        metrics_gauge_set(METRIC_THREAD_COUNT, NULL, (double)get_thread_count());

        for (uint32_t i = 0; i < mgr->collect_interval_ms / 100 && mgr->collector_running; i++) {
            cupolas_sleep_ms(100);
        }
    }

    return NULL;
}

static void *reporter_thread_func(void *arg)
{
    cupolas_monitoring_t *mgr = (cupolas_monitoring_t *)arg;

    while (mgr->reporter_running) {
        cupolas_sleep_ms(mgr->collect_interval_ms * 2);

        cupolas_rwlock_wrlock(&mgr->lock);

        metrics_export_prometheus(mgr->metrics_buffer, sizeof(mgr->metrics_buffer) - 1);
        mgr->metrics_buffer_size = strlen(mgr->metrics_buffer);
        mgr->last_report_time = metrics_get_timestamp_ns();

        cupolas_rwlock_unlock(&mgr->lock);
    }

    return NULL;
}

int cupolas_monitoring_start(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return AIRY_EINVAL;

    cupolas_rwlock_wrlock(&mgr->lock);

    if (mgr->status == MONITORING_STATUS_RUNNING) {
        cupolas_rwlock_unlock(&mgr->lock);
        return 0;
    }

    mgr->status = MONITORING_STATUS_STARTING;
    mgr->reporter_running = true;

    metrics_init(mgr->collect_interval_ms);

    metric_desc_t mem_desc = {.name = METRIC_PROCESS_MEMORY_BYTES,
                              .help = "Current process resident memory in bytes",
                              .type = METRIC_TYPE_GAUGE,
                              .label_names = NULL,
                              .label_count = 0};
    metrics_register(&mem_desc);

    metric_desc_t cpu_desc = {.name = METRIC_PROCESS_CPU_SECONDS,
                              .help = "Total CPU time consumed by process",
                              .type = METRIC_TYPE_GAUGE,
                              .label_names = NULL,
                              .label_count = 0};
    metrics_register(&cpu_desc);

    metric_desc_t thread_desc = {.name = METRIC_THREAD_COUNT,
                                 .help = "Number of threads in process",
                                 .type = METRIC_TYPE_GAUGE,
                                 .label_names = NULL,
                                 .label_count = 0};
    metrics_register(&thread_desc);

    mgr->collector_running = true;
    int ret = cupolas_thread_create(&mgr->collector_thread, collector_thread_func, mgr);
    if (ret != 0) {
        CUPOLAS_LOG_ERROR("monitoring: failed to create collector thread");
        mgr->collector_running = false;
    }

    if (mgr->manager.backend == MONITORING_BACKEND_PROMETHEUS ||
        mgr->manager.backend == MONITORING_BACKEND_ALL) {
        ret = cupolas_thread_create(&mgr->reporter_thread, reporter_thread_func, mgr);
        if (ret != 0) {
            CUPOLAS_LOG_ERROR("monitoring: failed to create reporter thread");
        }
    }

    mgr->status = MONITORING_STATUS_RUNNING;

    cupolas_rwlock_unlock(&mgr->lock);

    CUPOLAS_LOG("monitoring: started (collect_ms=%u)", mgr->collect_interval_ms);

    return 0;
}

void cupolas_monitoring_stop(cupolas_monitoring_t *mgr)
{
    if (!mgr)
        return;

    cupolas_rwlock_wrlock(&mgr->lock);

    if (mgr->status != MONITORING_STATUS_RUNNING && mgr->status != MONITORING_STATUS_STARTING) {
        cupolas_rwlock_unlock(&mgr->lock);
        return;
    }

    mgr->status = MONITORING_STATUS_STOPPING;
    mgr->reporter_running = false;

    mgr->collector_running = false;

    cupolas_rwlock_unlock(&mgr->lock);

    void *retval = NULL;
    cupolas_thread_join(mgr->reporter_thread, &retval);

    cupolas_thread_join(mgr->collector_thread, &retval);
    (void)retval;

    metrics_shutdown();

    cupolas_rwlock_wrlock(&mgr->lock);
    mgr->status = MONITORING_STATUS_STOPPED;
    cupolas_rwlock_unlock(&mgr->lock);

    CUPOLAS_LOG("monitoring: stopped");
}
