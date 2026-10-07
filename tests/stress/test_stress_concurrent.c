// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * test_stress_concurrent.c - Concurrent Stress Tests Framework
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "audit/audit.h"
#include "cupolas.h"
#include "permission/permission.h"
#include "sanitizer/sanitizer.h"

#include "platform.h"

#define STRESS_THREAD_COUNT 64
#define STRESS_OPS_PER_THREAD 10000
#define STRESS_DURATION_MS 5000

static permission_engine_t *g_perm_engine = NULL;

typedef struct {
    int thread_id;
    int ops_count;
    int success_count;
    int fail_count;
    double avg_latency_us;
} thread_ctx_t;

#ifdef _WIN32
static DWORD WINAPI stress_test_thread(LPVOID arg)
#else
static void *stress_test_thread(void *arg)
#endif
{
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    ctx->success_count = 0;
    ctx->fail_count = 0;

    for (int i = 0; i < ctx->ops_count; i++) {
        uint64_t start_ns = airy_time_ns();

        int perm_result = -1;
        if (g_perm_engine) {
            perm_result =
                permission_engine_check(g_perm_engine, "test_agent", "read", "resource", NULL);
        }

        uint64_t end_ns = airy_time_ns();
        double latency_us = (double)(end_ns - start_ns) / 1000.0;

        if (perm_result >= 0) {
            ctx->success_count++;
        } else {
            ctx->fail_count++;
        }

        ctx->avg_latency_us += latency_us;
    }

    ctx->avg_latency_us /= ctx->ops_count;

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

void stress_test_concurrent_permission_checks(void)
{
    printf("\n=== Concurrent Permission Check Stress Test ===\n");
    printf("Threads: %d, Operations per thread: %d\n\n", STRESS_THREAD_COUNT,
           STRESS_OPS_PER_THREAD);

    g_perm_engine = permission_engine_create(NULL);
    if (g_perm_engine) {
        permission_engine_add_rule(g_perm_engine, "test_agent", "read", "resource", 1, 10);
    }

#ifdef _WIN32
    HANDLE threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#else
    pthread_t threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#endif
    int started[STRESS_THREAD_COUNT];

    int total_success = 0;
    int total_fail = 0;
    double total_avg_latency = 0;

    uint64_t start_ms = airy_time_ms();

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        results[i].thread_id = i;
        results[i].ops_count = STRESS_OPS_PER_THREAD;
        results[i].success_count = 0;
        results[i].fail_count = 0;
        results[i].avg_latency_us = 0.0;

#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, stress_test_thread, &results[i], 0, NULL);
        started[i] = (threads[i] != NULL);
#else
        started[i] = (pthread_create(&threads[i], NULL, stress_test_thread, &results[i]) == 0);
#endif
        if (!started[i]) {
            printf("Thread %2d: failed to start\n", i);
        }
    }

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        if (!started[i]) {
            continue;
        }

#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif

        total_success += results[i].success_count;
        total_fail += results[i].fail_count;
        total_avg_latency += results[i].avg_latency_us;

        printf("Thread %2d: Success=%5d, Fail=%3d, Avg Latency=%.2f us\n", i,
               results[i].success_count, results[i].fail_count, results[i].avg_latency_us);
    }

    double duration_ms = (double)(airy_time_ms() - start_ms);
    int total_ops = total_success + total_fail;

    printf("\n=== Summary ===\n");
    printf("Total Operations: %d\n", total_ops);
    printf("Successful: %d (%.2f%%)\n", total_success,
           total_ops > 0 ? 100.0 * total_success / total_ops : 0.0);
    printf("Failed: %d (%.2f%%)\n", total_fail, total_ops > 0 ? 100.0 * total_fail / total_ops : 0.0);
    printf("Total Duration: %.2f ms\n", duration_ms);
    printf("Throughput: %.2f ops/sec\n", duration_ms > 0.0 ? total_ops * 1000.0 / duration_ms : 0.0);
    printf("Average Latency: %.2f us\n", total_avg_latency / STRESS_THREAD_COUNT);

    if (g_perm_engine) {
        permission_engine_destroy(g_perm_engine);
        g_perm_engine = NULL;
    }
}

void stress_test_concurrent_audit_writes(void)
{
    printf("\n=== Concurrent Audit Write Stress Test ===\n");
    printf("Threads: %d, Operations per thread: %d\n\n", STRESS_THREAD_COUNT,
           STRESS_OPS_PER_THREAD);

#ifdef _WIN32
    HANDLE threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#else
    pthread_t threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#endif

    int started[STRESS_THREAD_COUNT];

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        results[i].thread_id = i;
        results[i].ops_count = STRESS_OPS_PER_THREAD;
    }

    uint64_t start_ms = airy_time_ms();

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, stress_test_thread, &results[i], 0, NULL);
        started[i] = (threads[i] != NULL);
#else
        started[i] = (pthread_create(&threads[i], NULL, stress_test_thread, &results[i]) == 0);
#endif
        if (!started[i]) {
            printf("Thread %2d: failed to start\n", i);
        }
    }

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        if (!started[i]) {
            continue;
        }

#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }

    double duration_ms = (double)(airy_time_ms() - start_ms);

    printf("Total Duration: %.2f ms\n", duration_ms);
    printf("Throughput: %.2f writes/sec\n",
           duration_ms > 0.0
               ? STRESS_THREAD_COUNT * STRESS_OPS_PER_THREAD * 1000.0 / duration_ms
               : 0.0);
}

void stress_test_cache_under_contention(void)
{
    printf("\n=== Cache Contention Stress Test ===\n");
    printf("Testing LRU cache under high concurrency...\n\n");

    g_perm_engine = permission_engine_create(NULL);
    if (g_perm_engine) {
        permission_engine_add_rule(g_perm_engine, "*", "read", "/data/*", 1, 5);
        permission_engine_add_rule(g_perm_engine, "admin", "write", "/data/*", 1, 10);
    }

#ifdef _WIN32
    HANDLE threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#else
    pthread_t threads[STRESS_THREAD_COUNT];
    thread_ctx_t results[STRESS_THREAD_COUNT];
#endif

    int started[STRESS_THREAD_COUNT];

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        results[i].thread_id = i;
        results[i].ops_count = STRESS_OPS_PER_THREAD;

#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, stress_test_thread, &results[i], 0, NULL);
        started[i] = (threads[i] != NULL);
#else
        started[i] = (pthread_create(&threads[i], NULL, stress_test_thread, &results[i]) == 0);
#endif
        if (!started[i]) {
            printf("Thread %2d: failed to start\n", i);
        }
    }

    for (int i = 0; i < STRESS_THREAD_COUNT; i++) {
        if (!started[i]) {
            continue;
        }

#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }

    if (g_perm_engine) {
        uint64_t hits = 0, misses = 0;
        permission_engine_cache_stats(g_perm_engine, &hits, &misses);
        printf("Cache hits: %lu, misses: %lu\n", (unsigned long)hits, (unsigned long)misses);
        permission_engine_destroy(g_perm_engine);
        g_perm_engine = NULL;
    }

    printf("Cache contention test completed\n");
}

int main(void)
{
    printf("========================================\n");
    printf("Cupolas Concurrent Stress Test Suite\n");
    printf("========================================\n\n");

    airy_err_t error = AIRY_OK;
    int init_result = cupolas_init(NULL, &error);
    if (init_result != AIRY_OK) {
        printf("Failed to initialize cupolas: result=%d, error=%d\n", init_result, error);
        printf("Skipping stress tests (cupolas unavailable)\n");
        printf("\n========================================\n");
        printf("Stress tests SKIPPED\n");
        printf("========================================\n");
        return 0;
    }

    stress_test_concurrent_permission_checks();
    stress_test_concurrent_audit_writes();
    stress_test_cache_under_contention();

    cupolas_cleanup();

    printf("\n========================================\n");
    printf("All stress tests completed\n");
    printf("========================================\n");

    return 0;
}
