/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file svc_canary.c
 * @brief cupolas_d 金丝雀治理面（0.1.20 W6 策略侧适配器）。
 *
 * 将 products/canary 五态机挂载到 g_dpolicy 的 canary 挂载点，并以
 * 30s 对账周期驱动五态转移：灰度会话建立时执行 G30 准入（以运行集
 * 规则条数为行数代理，经 export JSON 的 rule_count 取数——gate 回调
 * 运行于引擎锁内，禁调任何拿引擎锁的 API，故度量移出 gate）、C0
 * 爆炸半径申报、C1 影子、C2 阶梯（10%→50%→100%，每级 ≥2h）；满级
 * 经门禁后先 adopt（manifest 落盘）再 promote（引擎固化），保证
 * 崩溃窗口内两侧一致。kill switch 走 500ms 分片快通道独立探测（不受
 * 30s 对账周期约束），命中即 revert + 回滚，最坏熔断时延约 1s。
 *
 * 生命周期约定：实例与进程同寿命，终态（ROLLED/ADOPTED 收尾）后
 * 治理面静默，gate 放行传统固化路径，重启开新一轮——避免宿主在
 * 引擎锁内读到悬垂实例，route 热路径保持无锁。挂载点缺席即旁路。
 */
#include "cupolas_d_internal.h"
#include "dynamic_policy_engine.h"
#include "canary.h"
#include "canary_sha256.h"
/* 治理线程经线程抽象双腿解析：无调度器实现时走 platform_process.h
 * 别名，airy_core 传播 AIRY_USE_SCHEDULER_THREAD_IMPL 时声明由
 * corekern task.h 提供（线程纳入调度器任务表记账）。两腿原型一致，
 * 调用点无需区分（notify_d/gateway_d 同范式）。 */
#include "platform.h"
#include "platform_process.h"
#ifdef AIRY_USE_SCHEDULER_THREAD_IMPL
#include "task.h"
#endif
#include "svc_logger.h"

#include <cjson/cJSON.h>
#include <string.h>

#define CAN_TICK_SLICES 60
#define CAN_SLICE_MS 500u

static canary_t *g_can;
static airy_atomic_int_t g_run;
static airy_thread_t g_thr;

static const char *const CAN_FILES[] = { "policy.json" };

/* FNV-1a：subject|action|resource 三元组采样盐（同请求恒同侧） */
static uint32_t can_hash3(const char *s, const char *a, const char *r)
{
    const char *p[3] = { s, a, r };
    uint32_t h = 2166136261u;

    for (int i = 0; i < 3; i++) {
        for (const char *q = p[i] ? p[i] : ""; *q; q++) {
            h ^= (uint8_t)*q;
            h *= 16777619u;
        }
        h ^= (uint8_t)'|';
        h *= 16777619u;
    }
    return h;
}

/* 锁内回调：只读 canary 原子态与 ks 缓存，禁调 dpolicy_* 锁 API。
 * COMMIT 非 0 一律拒绝（灰度会话禁旁路固化）；ACTIVATE 返回 1 分流
 * 建立灰度会话，灰度进行中拒绝新 activate（防 snap 覆盖回滚锚点），
 * 治理面终态后放行传统路径。 */
static int can_gate(dpolicy_canary_kind_t kind, void *ud)
{
    canary_state_t st;
    int busy;

    (void)ud;
    if (!g_can)
        return 0;
    st = canary_state(g_can);
    busy = st == CANARY_ST_SHADOW || st == CANARY_ST_CANARY;
    if (kind == DPOLICY_CANARY_COMMIT)
        return busy ? -1 : 0;
    if (kind == DPOLICY_CANARY_ACTIVATE) {
        if (busy)
            return -1;
        if (canary_ks_hit(g_can, airy_time_ms()))
            return -1;
        return st == CANARY_ST_NONE ? 1 : 0;
    }
    return 0;
}

static int can_route(const char *s, const char *a, const char *r, void *ud)
{
    (void)ud;
    if (!g_can)
        return 0;
    return canary_route(g_can, can_hash3(s, a, r));
}

static const dpolicy_canary_ops_t g_ops = {
    .gate = can_gate,
    .route = can_route,
    .user_data = NULL
};

/* 引擎运行集指纹：export JSON 串的 SHA-256，与 manifest 同源同算法 */
static int can_fp(uint8_t hash[32])
{
    char *json = NULL;

    if (!g_dpolicy || dpolicy_engine_export_policies_json(g_dpolicy, &json) != 0)
        return -1;
    sha256_buf(json, strlen(json), hash);
    cJSON_free(json);
    return 0;
}

/* 统一回滚：先恢复引擎旧集（会话未建立时无害），再落状态机终态 */
static void can_roll(void)
{
    if (g_dpolicy && dpolicy_canary_active(g_dpolicy) &&
        dpolicy_canary_revert(g_dpolicy) != 0)
        SVC_LOG_WARN("canary revert failed, engine session kept");
    if (canary_rollback(g_can) != 0)
        SVC_LOG_WARN("canary rollback deferred");
}

/* 运行集规则条数（G30 行数代理），失败返回 -1 由下轮重试 */
static int can_rules(size_t *out)
{
    char *json = NULL;
    cJSON *root;
    cJSON *n;
    size_t v = 0;

    if (!g_dpolicy || dpolicy_engine_export_policies_json(g_dpolicy, &json) != 0)
        return -1;
    root = cJSON_Parse(json);
    if (root) {
        n = cJSON_GetObjectItem(root, "rule_count");
        if (cJSON_IsNumber(n) && n->valueint > 0)
            v = (size_t)n->valueint;
        cJSON_Delete(root);
    }
    cJSON_free(json);
    *out = v;
    return v > 0 ? 0 : -1;
}

/* C0→C1→C2：灰度会话建立信号（引擎 active 而状态机仍在 NONE/PROPOSED） */
static void can_seed(uint64_t now)
{
    canary_blast_t b;
    size_t n;

    if (can_rules(&n) != 0)
        return;
    if (canary_admit(n, n) != 0) {
        SVC_LOG_WARN("canary G30 admit reject (rules=%zu), rolling back", n);
        can_roll();
        return;
    }
    b.module = "policy";
    b.files = CAN_FILES;
    b.nfiles = 1u;
    b.lines = n;
    if (canary_propose(g_can, &b) != 0 || canary_to_shadow(g_can) != 0 ||
        canary_to_canary(g_can, now) != 0) {
        can_roll();
        return;
    }
    SVC_LOG_INFO("canary session entered C2, 10%% canary");
}

/* C2 判定：驻留推进；满级经门禁后先 adopt 后 promote（崩溃窗口一致）。
 * 门禁申报语义：存活即 K3=0（崩溃则 tick 不复存在）；K1/K2 无运行时
 * 指标源前以"未观测到异常"申报；K5=采纳经 manifest 可追溯，
 * K6=爆炸半径已经 G30+申报约束。 */
static void can_judge(uint64_t now)
{
    canary_gates_t g = { CANARY_OK_FLOOR, CANARY_PERF_FLOOR, 0u, 0u,
                         CANARY_G_EXPLAIN | CANARY_G_BOUNDARY };
    uint8_t fp[32];
    int r = canary_step(g_can, now);

    if (r == -2)
        return;
    if (r == 0) {
        SVC_LOG_INFO("canary stage advanced to %u permille",
                     (unsigned)canary_permille(g_can));
        return;
    }
    if (r < 0) {
        can_roll();
        return;
    }
    if (canary_gates(&g) != 0) {
        SVC_LOG_WARN("canary gates rejected, rolling back");
        can_roll();
        return;
    }
    if (can_fp(fp) != 0)
        return;
    if (canary_adopt(g_can, fp, now) != 0) {
        SVC_LOG_WARN("canary adopt failed, retrying");
        return;
    }
    if (dpolicy_canary_promote(g_dpolicy) != 0)
        SVC_LOG_WARN("canary promote pending, will retry");
    else
        SVC_LOG_INFO("canary adopted and promoted");
}

/* kill switch 快通道：逐片探测（ks TTL ≤1s），命中即停止一切演化写入。
 * 30s 对账周期只负责状态推进，不得成为熔断时延下界。 */
static void can_watch(void)
{
    canary_state_t st;

    if (!g_can)
        return;
    if (!canary_ks_hit(g_can, airy_time_ms()))
        return;
    st = canary_state(g_can);
    if (st == CANARY_ST_ROLLED &&
        !(g_dpolicy && dpolicy_canary_active(g_dpolicy)))
        return;
    SVC_LOG_WARN("canary kill switch hit, rolling back");
    can_roll();
}

static void can_reckon(void)
{
    canary_state_t st;
    uint64_t now = airy_time_ms();

    if (!g_can || !g_dpolicy)
        return;
    st = canary_state(g_can);
    if (dpolicy_canary_active(g_dpolicy)) {
        if (st == CANARY_ST_NONE || st == CANARY_ST_PROPOSED)
            can_seed(now);
        else if (st == CANARY_ST_CANARY)
            can_judge(now);
        else if (st == CANARY_ST_SHADOW)
            canary_to_canary(g_can, now);
        else if (st == CANARY_ST_ADOPTED &&
                 dpolicy_canary_promote(g_dpolicy) != 0)
            SVC_LOG_WARN("canary promote pending, will retry");
    } else {
        if (st == CANARY_ST_SHADOW || st == CANARY_ST_CANARY) {
            SVC_LOG_WARN("canary engine session gone, rolling back");
            can_roll();
        } else if (st == CANARY_ST_ADOPTED) {
            uint8_t fp[32];

            if (can_fp(fp) == 0 && canary_verify(g_can, fp) == -2)
                SVC_LOG_WARN("canary manifest replay pending (base drift)");
        }
    }
}

static void *can_tick(void *arg)
{
    (void)arg;
    while (airy_atomic_load(&g_run)) {
        can_watch();
        can_reckon();
        for (int i = 0; i < CAN_TICK_SLICES && airy_atomic_load(&g_run); i++) {
            airy_sleep_ms(CAN_SLICE_MS);
            can_watch();
        }
    }
    return NULL;
}

int svc_canary_on(void)
{
    uint8_t fp[32];

    if (!g_dpolicy || g_can)
        return -1;
    canary_ks_env("AIRY_CUPOLAS_CANARY_KILL");
    if (canary_new(&g_can, airy_runtime_dir(), "policy") != 0)
        return -1;
    /* 启动对账：上次采纳的 manifest 与当前基线比对，漂移即标记待重放 */
    if (can_fp(fp) == 0 && canary_verify(g_can, fp) == -2)
        SVC_LOG_WARN("canary manifest replay pending (base drift)");
    if (dpolicy_set_canary_ops(g_dpolicy, &g_ops) != 0)
        goto fail;
    airy_atomic_store(&g_run, 1);
    if (airy_thread_create(&g_thr, can_tick, NULL) != 0) {
        airy_atomic_store(&g_run, 0);
        dpolicy_set_canary_ops(g_dpolicy, NULL);
        goto fail;
    }
    SVC_LOG_INFO("canary governor online (policy)");
    return 0;
fail:
    canary_free(g_can);
    g_can = NULL;
    return -1;
}

void svc_canary_off(void)
{
    if (!g_can)
        return;
    /* 时序强制：先 revert（ops 挂载时 set NULL 会被会话检查拒绝，
     * 且 NULL 后 revert 返回 -2 将永久悬挂 shadow），再停线程，最后
     * 摘挂载点并释放——join 后 gate/route 不再被调，free 无竞态 */
    if (g_dpolicy && dpolicy_canary_active(g_dpolicy))
        dpolicy_canary_revert(g_dpolicy);
    airy_atomic_store(&g_run, 0);
    airy_thread_join(g_thr, NULL);
    if (g_dpolicy)
        dpolicy_set_canary_ops(g_dpolicy, NULL);
    canary_free(g_can);
    g_can = NULL;
    SVC_LOG_INFO("canary governor offline");
}
