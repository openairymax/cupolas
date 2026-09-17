// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dpolicy_version.c
 * @brief Dynamic Policy Engine 版本管理（epoch SSoT）。
 *
 * 每次 commit/rollback 深拷贝运行集快照入版本历史（最近 32 版），
 * epoch 单调 +1；版本号 vN 即 epoch+1 的固化标签。
 */

#include "dpolicy_internal.h"

#include <stdio.h>
#include <string.h>

void dpol_version_free(dpolicy_version_t *v)
{
    if (!v)
        return;
    for (size_t i = 0; i < v->rule_count; i++)
        dpol_rule_free(&v->rules[i]);
    AIRY_FREE(v->rules);
    AIRY_FREE(v->created_by);
    AIRY_FREE(v->description);
    __builtin_memset(v, 0, sizeof(*v));
}

/* 深拷贝当前规则集到版本快照 */
int dpol_ver_snapshot(dpolicy_engine_t *e, dpolicy_version_t *v, const char *desc,
                      const char *by)
{
    __builtin_memset(v, 0, sizeof(*v));
    if (e->rule_count > 0) {
        v->rules = AIRY_CALLOC(e->rule_count, sizeof(dpolicy_rule_t));
        if (!v->rules)
            return -1;
        for (size_t i = 0; i < e->rule_count; i++) {
            dpol_rule_copy(&v->rules[i], &e->rules[i]);
            if ((e->rules[i].condition_json && e->rules[i].condition_json[0]) &&
                !v->rules[i].condition_json) {
                dpol_version_free(v);
                return -1;
            }
        }
    }
    v->rule_count = e->rule_count;
    v->created_at = dpol_now_ms();
    if (desc && desc[0])
        v->description = AIRY_STRDUP(desc);
    if (by && by[0])
        v->created_by = AIRY_STRDUP(by);
    return 0;
}

/* 锁内版本固化：快照当前运行集 → 版本历史 + epoch+1（commit/activate 共用） */
int dpol_commit_locked(dpolicy_engine_t *e, const char *description)
{
    if (e->version_count >= DPOLICY_MAX_VERSIONS) {
        /* 超出 32 版：丢弃最旧，保留最近 31 + 新 1 */
        dpol_version_free(&e->versions[0]);
        for (size_t i = 1; i < e->version_count; i++)
            e->versions[i - 1] = e->versions[i];
        e->version_count--;
    }
    dpolicy_version_t v;
    if (dpol_ver_snapshot(e, &v, description, NULL) != 0)
        return -3;
    char vtag[32];
    snprintf(vtag, sizeof(vtag), "v%llu", (unsigned long long)(e->epoch + 1));
    AIRY_STRNCPY_TERM(v.version, vtag, sizeof(v.version));
    e->versions[e->version_count++] = v;
    e->epoch++;
    return 0;
}

int dpolicy_engine_commit_version(dpolicy_engine_t *engine, const char *description)
{
    if (!engine)
        return -1;
    airy_mtx_lock(&engine->lock);
    int rc = dpol_commit_locked(engine, description);
    airy_mtx_unlock(&engine->lock);
    if (rc == 0)
        dpol_fire_change(engine, DPOLICY_CHANGE_COMMIT, NULL, NULL, NULL, description);
    return rc;
}

int dpolicy_engine_rollback(dpolicy_engine_t *engine, const char *version)
{
    if (!engine || !version)
        return -1;
    airy_mtx_lock(&engine->lock);
    int found = -1;
    for (size_t i = 0; i < engine->version_count; i++) {
        if (strcmp(engine->versions[i].version, version) == 0) {
            found = (int)i;
            break;
        }
    }
    if (found < 0) {
        airy_mtx_unlock(&engine->lock);
        return -2;
    }
    const dpolicy_version_t *target = &engine->versions[found];
    /* 用目标版本快照替换当前规则集 */
    if (target->rule_count > engine->rule_cap) {
        dpolicy_rule_t *nr = AIRY_REALLOC(engine->rules,
                                          target->rule_count * sizeof(dpolicy_rule_t));
        if (!nr) {
            airy_mtx_unlock(&engine->lock);
            return -3;
        }
        engine->rules = nr;
        engine->rule_cap = target->rule_count;
    }
    for (size_t i = 0; i < engine->rule_count; i++)
        dpol_rule_free(&engine->rules[i]);
    __builtin_memset(engine->rules, 0, engine->rule_cap * sizeof(dpolicy_rule_t));
    engine->rule_count = 0;
    for (size_t i = 0; i < target->rule_count; i++) {
        dpol_rule_copy(&engine->rules[i], &target->rules[i]);
        if ((target->rules[i].condition_json && target->rules[i].condition_json[0]) &&
            !engine->rules[i].condition_json) {
            airy_mtx_unlock(&engine->lock);
            return -3;
        }
    }
    engine->rule_count = target->rule_count;
    engine->epoch++;
    airy_mtx_unlock(&engine->lock);
    dpol_fire_change(engine, DPOLICY_CHANGE_ROLLBACK, NULL, NULL, NULL, version);
    return 0;
}
