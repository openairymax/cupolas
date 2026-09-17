// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dpolicy_internal.h
 * @brief Dynamic Policy Engine 内部共享契约（仅 src/policy 内可见）。
 *
 * 拆分布局：核心评估与 CRUD（dynamic_policy_engine.c）/
 * 版本管理（dpolicy_version.c）/ JSON 导入导出（dpolicy_json.c）。
 * epoch 单调递增为引擎 SSoT（commit/rollback +1），PEP 缓存以其为失效键。
 */

#ifndef CUPOLAS_DPOLICY_INTERNAL_H
#define CUPOLAS_DPOLICY_INTERNAL_H

#include "airy_memory.h"
#include "dynamic_policy_engine.h"
#include "platform_sync.h"

#include <stddef.h>
#include <stdint.h>

/* ── 引擎内部结构 ─────────────────────────────────────────────────── */

struct dpolicy_engine_s {
    dpolicy_conflict_strategy_t strategy;
    /* 运行集：check_permission 评估的唯一规则源（epoch SSoT 保护其变更） */
    dpolicy_rule_t *rules;
    size_t rule_count;
    size_t rule_cap;
    /* 暂存集（两段式生效）：policy.load 装载、policy.activate 提交到运行集。
     * load 不改变运行裁决与 epoch；activate 原子替换 + 版本固化 + epoch+1。 */
    dpolicy_rule_t *staged;
    size_t staged_count;
    size_t staged_cap;
    int staged_valid;
    /* 版本历史：每 commit/rollback 深拷贝快照，[0] 为最早，最近在尾 */
    dpolicy_version_t versions[DPOLICY_MAX_VERSIONS];
    size_t version_count;
    uint64_t epoch;
    dpolicy_change_callback_t cb;
    void *cb_ud;
    airy_mtx_t lock;
};

/* ── 跨文件共享内部函数（dpol_ 前缀防静态库符号冲突） ─────────────── */

uint64_t dpol_now_ms(void);

void dpol_rule_free(dpolicy_rule_t *r);
void dpol_rule_copy(dpolicy_rule_t *dst, const dpolicy_rule_t *src);

void dpol_version_free(dpolicy_version_t *v);
/* 深拷贝当前规则集到版本快照，失败返回 -1 */
int dpol_ver_snapshot(dpolicy_engine_t *e, dpolicy_version_t *v, const char *desc,
                      const char *by);

/* 变更回调（锁外调用约定由各触发点保证） */
void dpol_fire_change(dpolicy_engine_t *e, dpolicy_change_type_t type, const char *rule_id,
                      const char *old_json, const char *new_json, const char *by);

/* 锁内版本固化：快照当前运行集 → 版本历史 + epoch+1（commit/activate 共用） */
int dpol_commit_locked(dpolicy_engine_t *e, const char *description);

#endif /* CUPOLAS_DPOLICY_INTERNAL_H */
