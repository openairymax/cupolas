/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * dpolicy_canary.c - dpolicy 灰度会话机制（W6 挂载点，纯机制零策略）。
 *
 * 灰度叠加于即时发布：activate 经 gate 分流（gate==1）时旧集深拷入
 * shadow、新集 live 替换、epoch 不变不固化版本；evaluate 按 route 采样
 * 分流（FNV-1a 保证同请求元组恒同侧）；promote 固化新集为正式版本，
 * revert 以 shadow 换回运行集并 epoch+1。gate/route 由宿主注入，缺席
 * 即旁路，引擎行为与传统路径完全一致。
 */
#include "dpolicy_internal.h"

/* 采样散列（FNV-1a）属宿主策略面：引擎机制只负责按 route 回调
 * 的裁决分流，不固化任何采样策略。 */

int dpol_can_gate(dpolicy_engine_t *e, dpolicy_canary_kind_t kind)
{
    if (!e->canary || !e->canary->gate)
        return 0;
    return e->canary->gate(kind, e->canary->user_data);
}

void dpol_can_source(const dpolicy_engine_t *e, const char *subject, const char *action,
                     const char *resource, const dpolicy_rule_t **rules, size_t *count)
{
    *rules = e->rules;
    *count = e->rule_count;
    if (e->canary && e->shadow_active && e->canary->route &&
        e->canary->route(subject, action, resource, e->canary->user_data) == 0) {
        *rules = e->shadow;
        *count = e->shadow_count;
    }
}

int dpol_can_snap(dpolicy_engine_t *e)
{
    size_t cap = e->rule_count > 0 ? e->rule_count : 8;
    dpolicy_rule_t *sh = AIRY_CALLOC(cap, sizeof(*sh));
    size_t i;

    if (!sh)
        return -1;
    for (i = 0; i < e->rule_count; i++) {
        dpol_rule_copy(&sh[i], &e->rules[i]);
        if ((e->rules[i].condition_json && e->rules[i].condition_json[0]) &&
            !sh[i].condition_json) {
            while (i > 0)
                dpol_rule_free(&sh[--i]);
            AIRY_FREE(sh);
            return -1;
        }
    }
    for (i = 0; e->shadow && i < e->shadow_count; i++)
        dpol_rule_free(&e->shadow[i]);
    AIRY_FREE(e->shadow);
    e->shadow = sh;
    e->shadow_cap = cap;
    e->shadow_count = e->rule_count;
    return 0;
}

void dpol_can_free(dpolicy_engine_t *e)
{
    size_t i;

    for (i = 0; e->shadow && i < e->shadow_count; i++)
        dpol_rule_free(&e->shadow[i]);
    AIRY_FREE(e->shadow);
    e->shadow = NULL;
    e->shadow_count = 0;
    e->shadow_cap = 0;
    e->shadow_active = 0;
}

int dpolicy_set_canary_ops(dpolicy_engine_t *e, const dpolicy_canary_ops_t *ops)
{
    if (!e)
        return -1;
    airy_mtx_lock(&e->lock);
    if (e->shadow_active) {
        airy_mtx_unlock(&e->lock);
        return -2;
    }
    e->canary = ops;
    airy_mtx_unlock(&e->lock);
    return 0;
}

int dpolicy_canary_active(dpolicy_engine_t *e)
{
    int on;

    if (!e)
        return 0;
    airy_mtx_lock(&e->lock);
    on = e->shadow_active;
    airy_mtx_unlock(&e->lock);
    return on;
}

int dpolicy_canary_revert(dpolicy_engine_t *e)
{
    dpolicy_rule_t *sh;
    size_t sh_count, sh_cap, i;

    if (!e)
        return -1;
    airy_mtx_lock(&e->lock);
    if (!e->shadow_active || !e->canary) {
        airy_mtx_unlock(&e->lock);
        return -2;
    }
    sh = e->shadow;
    sh_count = e->shadow_count;
    sh_cap = e->shadow_cap;
    if (!sh) {
        /* 旧集为空：兜底空数组维持 live_replace 不变量（rules 非 NULL/cap>=8） */
        sh = AIRY_CALLOC(8, sizeof(*sh));
        if (!sh) {
            airy_mtx_unlock(&e->lock);
            return -3;
        }
        sh_cap = 8;
    }
    for (i = 0; i < e->rule_count; i++)
        dpol_rule_free(&e->rules[i]);
    AIRY_FREE(e->rules);
    e->rules = sh;
    e->rule_count = sh_count;
    e->rule_cap = sh_cap;
    e->shadow = NULL;
    e->shadow_count = 0;
    e->shadow_cap = 0;
    e->shadow_active = 0;
    e->epoch++;
    airy_mtx_unlock(&e->lock);
    dpol_fire_change(e, DPOLICY_CHANGE_ROLLBACK, NULL, NULL, NULL, "canary_revert");
    return 0;
}

int dpolicy_canary_promote(dpolicy_engine_t *e)
{
    int rc;

    if (!e)
        return -1;
    airy_mtx_lock(&e->lock);
    if (!e->shadow_active || !e->canary) {
        airy_mtx_unlock(&e->lock);
        return -2;
    }
    dpol_can_free(e);
    rc = dpol_commit_locked(e, "canary_promote");
    airy_mtx_unlock(&e->lock);
    if (rc == 0)
        dpol_fire_change(e, DPOLICY_CHANGE_COMMIT, NULL, NULL, NULL, "canary_promote");
    return rc;
}
