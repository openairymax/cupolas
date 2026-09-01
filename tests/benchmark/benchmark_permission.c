// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file benchmark_permission.c
 * @brief Permission check performance baseline (M2-S1, 0.1.9 §3.4 前置).
 *
 * 为 cupolas PDP 化（M2）建立权限检查延迟与 PEP 缓存命中率基线：
 *   - 冷路径：不同 key 首次检查（规则匹配 + 缓存写入）
 *   - 热路径：同 key 重复检查（缓存命中，零延迟热路径）
 *   - 混合负载：80% 热 key + 20% 冷 key 的命中率与平均延迟基线
 *
 * 基准输出 p50/p99，供 M2-S5 PEP 缓存（epoch 失效键）落地后对比
 * 验收（策略变更 runtime 生效 < 1s；热路径命中率 ≥ 覆盖）。
 *
 * STRICT 合规模式毒化 printf/fprintf，输出统一走 fputs + vsnprintf。
 */

#include "../src/permission/permission.h"

#include "airy_memory.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_ITERS 20000
#define BENCH_WARMUP 1000
#define BENCH_HOT_KEYS 64

typedef struct {
    const char *name;
    double avg_us;
    double min_us;
    double max_us;
    double p50_us;
    double p99_us;
} bench_result_t;

static void out(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int cmp_u64(const void *a, const void *b)
{
    return (*(const uint64_t *)a > *(const uint64_t *)b) -
           (*(const uint64_t *)a < *(const uint64_t *)b);
}

static void finish(uint64_t *times, size_t n, const char *name)
{
    qsort(times, n, sizeof(uint64_t), cmp_u64);
    double sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += times[i];
    out("  %-32s avg=%8.2fus min=%8.2f max=%8.2f p50=%8.2f p99=%8.2f\n", name,
        sum / (double)n, (double)times[0], (double)times[n - 1],
        (double)times[n / 2], (double)times[n * 99 / 100]);
}

static permission_engine_t *make_engine(void)
{
    permission_engine_t *e = permission_engine_create(NULL);
    if (!e)
        return NULL;
    /* 基础规则：* 读默认允许；写默认拒绝；敏感资源覆盖 */
    permission_engine_add_rule(e, "*", "read", "*", 1, 1);
    permission_engine_add_rule(e, "*", "write", "*", 0, 1);
    permission_engine_add_rule(e, "*", "write", "/data/tmp/*", 1, 10);
    permission_engine_add_rule(e, "agent_admin", "*", "*", 1, 100);
    return e;
}

static void bench_cold_path(permission_engine_t *e, int iters)
{
    uint64_t *t = (uint64_t *)AIRY_MALLOC((size_t)iters * sizeof(uint64_t));
    if (!t)
        return;
    for (int i = 0; i < iters; i++) {
        char agent[48], res[64];
        snprintf(agent, sizeof(agent), "agent_%d", i);
        snprintf(res, sizeof(res), "/data/items/item_%d", i);
        uint64_t s = now_us();
        permission_engine_check(e, agent, "read", res, NULL);
        t[i] = now_us() - s;
    }
    finish(t, (size_t)iters, "cold path (cache miss)");
    AIRY_FREE(t);
}

static void bench_hot_path(permission_engine_t *e, int iters)
{
    uint64_t *t = (uint64_t *)AIRY_MALLOC((size_t)iters * sizeof(uint64_t));
    if (!t)
        return;
    for (int i = 0; i < iters; i++) {
        uint64_t s = now_us();
        permission_engine_check(e, "agent_admin", "write", "/data/tmp/x.bin", NULL);
        t[i] = now_us() - s;
    }
    finish(t, (size_t)iters, "hot path (cache hit)");
    AIRY_FREE(t);
}

static void bench_mixed_load(permission_engine_t *e, int iters)
{
    uint64_t *t = (uint64_t *)AIRY_MALLOC((size_t)iters * sizeof(uint64_t));
    if (!t)
        return;
    uint64_t hits = 0, misses = 0;
    for (int i = 0; i < iters; i++) {
        char agent[48], res[64];
        if (i % 5 != 0) {
            /* 80% 热 key：重复命中 */
            snprintf(agent, sizeof(agent), "agent_%d", i % BENCH_HOT_KEYS);
            snprintf(res, sizeof(res), "/data/tmp/f_%d.txt", i % BENCH_HOT_KEYS);
        } else {
            /* 20% 冷 key：新 key 首次检查 */
            snprintf(agent, sizeof(agent), "agent_cold_%d", i);
            snprintf(res, sizeof(res), "/data/items/c_%d", i);
        }
        uint64_t s = now_us();
        permission_engine_check(e, agent, "read", res, NULL);
        t[i] = now_us() - s;
        if (i % 5 != 0)
            hits++;
        else
            misses++;
    }
    finish(t, (size_t)iters, "mixed 80/20 load");

    uint64_t hit_cnt = 0, miss_cnt = 0;
    permission_engine_cache_stats(e, &hit_cnt, &miss_cnt);
    out("  cache stats: hits=%llu misses=%llu hit_rate=%.2f%% (load hits=%llu miss=%llu)\n",
        (unsigned long long)hit_cnt, (unsigned long long)miss_cnt,
        (hit_cnt + miss_cnt) > 0 ? 100.0 * (double)hit_cnt / (double)(hit_cnt + miss_cnt) : 0.0,
        (unsigned long long)hits, (unsigned long long)misses);
    AIRY_FREE(t);
}

int main(int argc, char *argv[])
{
    int iters = BENCH_ITERS;
    if (argc > 1) {
        iters = atoi(argv[1]);
        if (iters < 100)
            iters = 100;
    }

    out("========================================\n");
    out("  AgentRT Cupolas Permission Baseline\n");
    out("  Iterations: %d\n", iters);
    out("========================================\n");

    permission_engine_t *e = make_engine();
    if (!e) {
        out("  FAILED: cannot create permission engine\n");
        return 1;
    }

    /* 预热 */
    for (int i = 0; i < BENCH_WARMUP; i++)
        permission_engine_check(e, "agent_warm", "read", "/data/warm", NULL);

    bench_cold_path(e, iters);
    bench_hot_path(e, iters);
    bench_mixed_load(e, iters);

    permission_engine_destroy(e);
    out("========================================\n");
    out("  Baseline complete (M2-S1)\n");
    out("========================================\n");
    return 0;
}
