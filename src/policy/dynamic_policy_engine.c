// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dynamic_policy_engine.c
 * @brief Dynamic Policy Engine 核心实现。
 *
 * 运行时策略引擎核心面：生命周期 / 规则 CRUD / 匹配评估（fail-closed）/
 * 冲突检测与消解 / 回调与合规验证。版本管理见 dpolicy_version.c，
 * JSON 导入导出与两段式生效见 dpolicy_json.c。
 *
 * epoch 单调递增为本引擎的 SSoT（每次 commit/rollback +1），PEP 缓存
 * 以 epoch 为失效键。匹配语义（fail-closed）：无匹配
 * 规则默认 DENY；规则匹配含 subject/action/resource 通配（glob *）+
 * 时间窗口 + enabled 门控。
 */

#include "dpolicy_internal.h"

#include <cjson/cJSON.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── 内部工具 ─────────────────────────────────────────────────────── */

/* 简单 glob：* 匹配任意序列（含空），其余字面匹配 */
static int pat_match(const char *pat, const char *text)
{
    if (!pat || !*pat || !text)
        return 0;
    const char *p = pat;
    const char *t = text;
    while (*p) {
        if (*p == '*') {
            while (*p == '*')
                p++;
            if (!*p)
                return 1;
            for (const char *q = t;; q++) {
                if (pat_match(p, q))
                    return 1;
                if (!*q)
                    break;
            }
            return 0;
        }
        if (*t != *p)
            return 0;
        p++;
        t++;
    }
    return (*t == '\0');
}

uint64_t dpol_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

void dpol_rule_free(dpolicy_rule_t *r)
{
    if (!r)
        return;
    AIRY_FREE(r->condition_json);
}

void dpol_rule_copy(dpolicy_rule_t *dst, const dpolicy_rule_t *src)
{
    __builtin_memset(dst, 0, sizeof(*dst));
    AIRY_STRNCPY_TERM(dst->id, src->id, sizeof(dst->id));
    AIRY_STRNCPY_TERM(dst->name, src->name, sizeof(dst->name));
    dst->effect = src->effect;
    AIRY_STRNCPY_TERM(dst->subject_pattern, src->subject_pattern, sizeof(dst->subject_pattern));
    AIRY_STRNCPY_TERM(dst->action_pattern, src->action_pattern, sizeof(dst->action_pattern));
    AIRY_STRNCPY_TERM(dst->resource_pattern, src->resource_pattern, sizeof(dst->resource_pattern));
    if (src->condition_json && src->condition_json[0])
        dst->condition_json = AIRY_STRDUP(src->condition_json);
    dst->priority = src->priority;
    dst->valid_from = src->valid_from;
    dst->valid_until = src->valid_until;
    dst->enabled = src->enabled;
}

void dpol_fire_change(dpolicy_engine_t *e, dpolicy_change_type_t type, const char *rule_id,
                      const char *old_json, const char *new_json, const char *by)
{
    if (!e->cb)
        return;
    dpolicy_change_record_t rec;
    __builtin_memset(&rec, 0, sizeof(rec));
    rec.type = type;
    AIRY_STRNCPY_TERM(rec.rule_id, rule_id ? rule_id : "", sizeof(rec.rule_id));
    rec.old_value_json = (char *)old_json;
    rec.new_value_json = (char *)new_json;
    rec.timestamp = dpol_now_ms();
    rec.changed_by = (char *)(by ? by : "");
    e->cb(&rec, e->cb_ud);
}

/* 规则是否命中（glob + 时间窗口 + enabled） */
static int rule_matches(const dpolicy_rule_t *r, const char *subject, const char *action,
                        const char *resource)
{
    if (!r->enabled)
        return 0;
    if (r->valid_from > 0 && dpol_now_ms() < r->valid_from)
        return 0;
    if (r->valid_until > 0 && dpol_now_ms() > r->valid_until)
        return 0;
    if (r->subject_pattern[0] && !pat_match(r->subject_pattern, subject))
        return 0;
    if (r->action_pattern[0] && !pat_match(r->action_pattern, action))
        return 0;
    if (r->resource_pattern[0] && !pat_match(r->resource_pattern, resource))
        return 0;
    return 1;
}

/* 两条规则是否在 action/resource 空间重叠（冲突候选） */
static int rules_overlap(const dpolicy_rule_t *a, const dpolicy_rule_t *b)
{
    /* 效果相同不构成冲突 */
    if (a->effect == b->effect)
        return 0;
    if (a->action_pattern[0] && b->action_pattern[0] &&
        !pat_match(a->action_pattern, b->action_pattern) &&
        !pat_match(b->action_pattern, a->action_pattern))
        return 0;
    if (a->resource_pattern[0] && b->resource_pattern[0] &&
        !pat_match(a->resource_pattern, b->resource_pattern) &&
        !pat_match(b->resource_pattern, a->resource_pattern))
        return 0;
    return 1;
}

static int rule_index(const dpolicy_engine_t *e, const char *rule_id)
{
    for (size_t i = 0; i < e->rule_count; i++) {
        if (strcmp(e->rules[i].id, rule_id) == 0)
            return (int)i;
    }
    return -1;
}

/* ── 生命周期 ─────────────────────────────────────────────────────── */

dpolicy_engine_t *dpolicy_engine_create(dpolicy_conflict_strategy_t default_strategy)
{
    dpolicy_engine_t *e = AIRY_CALLOC(1, sizeof(dpolicy_engine_t));
    if (!e)
        return NULL;
    e->strategy = default_strategy;
    e->rule_cap = 64;
    e->rules = AIRY_CALLOC(e->rule_cap, sizeof(dpolicy_rule_t));
    if (!e->rules) {
        AIRY_FREE(e);
        return NULL;
    }
    if (airy_mtx_init(&e->lock) != 0) {
        AIRY_FREE(e->rules);
        AIRY_FREE(e);
        return NULL;
    }
    return e;
}

void dpolicy_engine_destroy(dpolicy_engine_t *engine)
{
    if (!engine)
        return;
    airy_mtx_lock(&engine->lock);
    for (size_t i = 0; i < engine->rule_count; i++)
        dpol_rule_free(&engine->rules[i]);
    AIRY_FREE(engine->rules);
    for (size_t i = 0; i < engine->staged_count; i++)
        dpol_rule_free(&engine->staged[i]);
    AIRY_FREE(engine->staged);
    for (size_t i = 0; i < engine->version_count; i++)
        dpol_version_free(&engine->versions[i]);
    airy_mtx_unlock(&engine->lock);
    airy_mtx_destroy(&engine->lock);
    AIRY_FREE(engine);
}

/* ── 规则管理 ─────────────────────────────────────────────────────── */

int dpolicy_engine_add_rule(dpolicy_engine_t *engine, const dpolicy_rule_t *rule)
{
    if (!engine || !rule || !rule->id[0])
        return -1;
    airy_mtx_lock(&engine->lock);
    if (rule_index(engine, rule->id) >= 0) {
        airy_mtx_unlock(&engine->lock);
        return -2;
    }
    if (engine->rule_count >= DPOLICY_MAX_RULES) {
        airy_mtx_unlock(&engine->lock);
        return -4;
    }
    if (engine->rule_count >= engine->rule_cap) {
        /* 运行集可能被 activate(空暂存) 清空为 NULL/cap=0：首次增长兜底 64 */
        size_t nc = engine->rule_cap > 0 ? engine->rule_cap * 2 : 64;
        dpolicy_rule_t *nr = AIRY_REALLOC(engine->rules, nc * sizeof(dpolicy_rule_t));
        if (!nr) {
            airy_mtx_unlock(&engine->lock);
            return -3;
        }
        engine->rules = nr;
        engine->rule_cap = nc;
    }
    dpol_rule_copy(&engine->rules[engine->rule_count], rule);
    if ((rule->condition_json && rule->condition_json[0]) &&
        !engine->rules[engine->rule_count].condition_json) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    engine->rule_count++;
    airy_mtx_unlock(&engine->lock);
    dpol_fire_change(engine, DPOLICY_CHANGE_ADD, rule->id, NULL, rule->condition_json,
                     rule->name);
    return 0;
}

int dpolicy_engine_remove_rule(dpolicy_engine_t *engine, const char *rule_id)
{
    if (!engine || !rule_id)
        return -1;
    airy_mtx_lock(&engine->lock);
    int idx = rule_index(engine, rule_id);
    if (idx < 0) {
        airy_mtx_unlock(&engine->lock);
        return -2;
    }
    dpol_rule_free(&engine->rules[idx]);
    for (size_t i = (size_t)idx; i + 1 < engine->rule_count; i++)
        engine->rules[i] = engine->rules[i + 1];
    __builtin_memset(&engine->rules[engine->rule_count - 1], 0,
                     sizeof(dpolicy_rule_t));
    engine->rule_count--;
    airy_mtx_unlock(&engine->lock);
    dpol_fire_change(engine, DPOLICY_CHANGE_REMOVE, rule_id, NULL, NULL, NULL);
    return 0;
}

int dpolicy_engine_update_rule(dpolicy_engine_t *engine, const char *rule_id,
                               const dpolicy_rule_t *new_rule)
{
    if (!engine || !rule_id || !new_rule)
        return -1;
    airy_mtx_lock(&engine->lock);
    int idx = rule_index(engine, rule_id);
    if (idx < 0) {
        airy_mtx_unlock(&engine->lock);
        return -2;
    }
    dpolicy_rule_t old = engine->rules[idx];
    dpolicy_rule_t fresh;
    __builtin_memset(&fresh, 0, sizeof(fresh));
    dpol_rule_copy(&fresh, new_rule);
    if ((new_rule->condition_json && new_rule->condition_json[0]) &&
        !fresh.condition_json) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    engine->rules[idx] = fresh;
    airy_mtx_unlock(&engine->lock);
    /* fire 在锁外、free old 之前：回调可安全读取 old/new 条件 JSON */
    dpol_fire_change(engine, DPOLICY_CHANGE_UPDATE, rule_id, old.condition_json,
                     fresh.condition_json, new_rule->name);
    dpol_rule_free(&old);
    return 0;
}

/* ── 评估（fail-closed：无匹配默认 DENY） ─────────────────────────── */

/* 锁内评估：返回效果；matched 输出是否命中（可 NULL，服务层 overlay 用） */
static dpolicy_effect_t eval_locked(const dpolicy_engine_t *engine, const char *subject,
                                    const char *action, const char *resource, int *matched)
{
    dpolicy_effect_t result = DPOLICY_EFFECT_DENY;
    int matched_any = 0;
    int best_prio = -1;
    dpolicy_effect_t best_effect = DPOLICY_EFFECT_DENY;
    int has_deny = 0, has_allow = 0, has_cond = 0;

    for (size_t i = 0; i < engine->rule_count; i++) {
        const dpolicy_rule_t *r = &engine->rules[i];
        if (!rule_matches(r, subject, action, resource))
            continue;
        matched_any = 1;
        if (r->effect == DPOLICY_EFFECT_DENY)
            has_deny = 1;
        else if (r->effect == DPOLICY_EFFECT_ALLOW)
            has_allow = 1;
        else
            has_cond = 1;
        if ((int)r->priority > best_prio) {
            best_prio = (int)r->priority;
            best_effect = r->effect;
        }
    }

    if (matched_any) {
        switch (engine->strategy) {
        case DPOLICY_CONFLICT_DENY_WINS:
            result = has_deny ? DPOLICY_EFFECT_DENY : (has_cond ? DPOLICY_EFFECT_CONDITIONAL :
                                                                    DPOLICY_EFFECT_ALLOW);
            break;
        case DPOLICY_CONFLICT_ALLOW_WINS:
            result = has_allow ? DPOLICY_EFFECT_ALLOW : (has_cond ? DPOLICY_EFFECT_CONDITIONAL :
                                                                    DPOLICY_EFFECT_DENY);
            break;
        case DPOLICY_CONFLICT_HIGHEST_PRIORITY:
            result = best_effect;
            break;
        case DPOLICY_CONFLICT_MOST_RESTRICTIVE:
            result = has_deny ? DPOLICY_EFFECT_DENY : (has_cond ? DPOLICY_EFFECT_CONDITIONAL :
                                                                    DPOLICY_EFFECT_ALLOW);
            break;
        default:
            result = best_effect;
            break;
        }
    }
    if (matched)
        *matched = matched_any;
    return result;
}

dpolicy_effect_t dpolicy_engine_evaluate(dpolicy_engine_t *engine, const char *subject,
                                         const char *action, const char *resource,
                                         const char *context_json)
{
    (void)context_json; /* 条件表达式求值暂未启用，预留扩展槽 */
    if (!engine || !subject || !action || !resource)
        return DPOLICY_EFFECT_DENY;

    airy_mtx_lock(&engine->lock);
    dpolicy_effect_t result = eval_locked(engine, subject, action, resource, NULL);
    airy_mtx_unlock(&engine->lock);
    return result;
}

dpolicy_effect_t dpolicy_eval_match(dpolicy_engine_t *engine, const char *subject,
                                           const char *action, const char *resource,
                                           const char *context_json, int *matched)
{
    (void)context_json;
    if (matched)
        *matched = 0;
    if (!engine || !subject || !action || !resource)
        return DPOLICY_EFFECT_DENY;

    airy_mtx_lock(&engine->lock);
    dpolicy_effect_t result = eval_locked(engine, subject, action, resource, matched);
    airy_mtx_unlock(&engine->lock);
    return result;
}

/* ── 冲突检测与消解 ───────────────────────────────────────────────── */

/* 锁内收集给定规则集的重叠异效对（live / staged 共用） */
static int overlaps_collect(const dpolicy_rule_t *rules, size_t n,
                            dpolicy_conflict_strategy_t strategy,
                            dpolicy_conflict_t **conflicts, size_t *conflict_count)
{
    size_t cap = n * n + 1;
    dpolicy_conflict_t *out = AIRY_CALLOC(cap, sizeof(dpolicy_conflict_t));
    if (!out)
        return -3;
    size_t c = 0;
    for (size_t i = 0; i < n && c < DPOLICY_MAX_CONFLICTS; i++) {
        for (size_t j = i + 1; j < n && c < DPOLICY_MAX_CONFLICTS; j++) {
            if (!rules_overlap(&rules[i], &rules[j]))
                continue;
            AIRY_STRNCPY_TERM(out[c].rule_a_id, rules[i].id, sizeof(out[c].rule_a_id));
            AIRY_STRNCPY_TERM(out[c].rule_b_id, rules[j].id, sizeof(out[c].rule_b_id));
            out[c].resolution = strategy;
            snprintf(out[c].reason, sizeof(out[c].reason),
                     "overlapping scope with divergent effects");
            c++;
        }
    }
    *conflicts = out;
    *conflict_count = c;
    return 0;
}

int dpolicy_engine_detect_conflicts(dpolicy_engine_t *engine, dpolicy_conflict_t **conflicts,
                                    size_t *conflict_count)
{
    if (!engine || !conflicts || !conflict_count)
        return -1;
    airy_mtx_lock(&engine->lock);
    int rc = overlaps_collect(engine->rules, engine->rule_count, engine->strategy, conflicts,
                              conflict_count);
    airy_mtx_unlock(&engine->lock);
    return rc;
}

int dpolicy_stage_check(dpolicy_engine_t *engine,
                                           dpolicy_conflict_t **conflicts,
                                           size_t *conflict_count)
{
    if (!engine || !conflicts || !conflict_count)
        return -1;
    airy_mtx_lock(&engine->lock);
    int rc = overlaps_collect(engine->staged, engine->staged_count, engine->strategy, conflicts,
                              conflict_count);
    airy_mtx_unlock(&engine->lock);
    return rc;
}

int dpolicy_engine_resolve_conflict(dpolicy_engine_t *engine, const dpolicy_conflict_t *conflict)
{
    if (!engine || !conflict)
        return -1;
    /* 冲突消解策略已在 evaluate 时按 engine->strategy 生效；
     * 此处将显式消解记录固化到默认策略（幂等）。 */
    airy_mtx_lock(&engine->lock);
    engine->strategy = conflict->resolution;
    airy_mtx_unlock(&engine->lock);
    return 0;
}

/* ── 回调 / 合规 / 统计 ───────────────────────────────────────────── */

int dpolicy_engine_set_change_callback(dpolicy_engine_t *engine, dpolicy_change_callback_t callback,
                                       void *user_data)
{
    if (!engine)
        return -1;
    airy_mtx_lock(&engine->lock);
    engine->cb = callback;
    engine->cb_ud = user_data;
    airy_mtx_unlock(&engine->lock);
    return 0;
}

int dpolicy_engine_validate_compliance(dpolicy_engine_t *engine, const char *standard,
                                       char **report_json)
{
    if (!engine || !standard || !report_json)
        return -1;
    airy_mtx_lock(&engine->lock);
    /* 合规基元：必须存在兜底 deny（fail-closed）规则 */
    int has_deny_all = 0;
    int has_allow_any = 0;
    for (size_t i = 0; i < engine->rule_count; i++) {
        const dpolicy_rule_t *r = &engine->rules[i];
        if (r->effect == DPOLICY_EFFECT_DENY && r->subject_pattern[0] == '*' &&
            r->action_pattern[0] == '*' && r->resource_pattern[0] == '*')
            has_deny_all = 1;
        if (r->effect == DPOLICY_EFFECT_ALLOW && r->subject_pattern[0] == '*' &&
            r->action_pattern[0] == '*' && r->resource_pattern[0] == '*')
            has_allow_any = 1;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "standard", standard);
    cJSON_AddBoolToObject(root, "has_fail_closed_deny", has_deny_all ? 1 : 0);
    cJSON_AddBoolToObject(root, "has_open_allow", has_allow_any ? 1 : 0);
    cJSON_AddBoolToObject(root, "pass",
                          (has_deny_all ? 1 : 0));
    airy_mtx_unlock(&engine->lock);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out)
        return -3;
    *report_json = out;
    return 0;
}

size_t dpolicy_engine_get_rule_count(dpolicy_engine_t *engine)
{
    return engine ? engine->rule_count : 0;
}

size_t dpolicy_staged_count(dpolicy_engine_t *engine)
{
    return engine ? engine->staged_count : 0;
}

int dpolicy_has_staged(dpolicy_engine_t *engine)
{
    return engine ? engine->staged_valid : 0;
}

size_t dpolicy_engine_get_version_count(dpolicy_engine_t *engine)
{
    return engine ? engine->version_count : 0;
}

uint64_t dpolicy_engine_get_epoch(dpolicy_engine_t *engine)
{
    return engine ? engine->epoch : 0;
}

dpolicy_conflict_strategy_t dpolicy_engine_get_strategy(dpolicy_engine_t *engine)
{
    return engine ? engine->strategy : DPOLICY_CONFLICT_DENY_WINS;
}
