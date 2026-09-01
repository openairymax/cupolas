// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dynamic_policy_engine.c
 * @brief Dynamic Policy Engine implementation (M2-S2, 0.1.9 §3.2 PDP).
 *
 * 运行时策略引擎：版本管理（32 版历史）/ 冲突消解（4 策略）/ 热更新 /
 * 回滚。epoch 单调递增为本引擎的 SSoT（每次 commit/rollback +1），
 * PEP 缓存以 epoch 为失效键（M2-S5 落地）。
 *
 * 匹配语义（fail-closed）：无匹配规则默认 DENY；规则匹配含 subject /
 * action / resource 通配（glob *）+ 时间窗口 + enabled 门控。
 */

#include "airy_memory.h"
#include "dynamic_policy_engine.h"
#include "error.h"
#include "platform_sync.h"

#include <cjson/cJSON.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── 内部结构 ─────────────────────────────────────────────────────── */

struct dpolicy_engine_s {
    dpolicy_conflict_strategy_t strategy;
    dpolicy_rule_t *rules;
    size_t rule_count;
    size_t rule_cap;
    /* 版本历史：每 commit/rollback 深拷贝快照，[0] 为最早，最近在尾 */
    dpolicy_version_t versions[DPOLICY_MAX_VERSIONS];
    size_t version_count;
    uint64_t epoch;
    dpolicy_change_callback_t cb;
    void *cb_ud;
    airy_mtx_t lock;
};

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

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void rule_free(dpolicy_rule_t *r)
{
    if (!r)
        return;
    AIRY_FREE(r->condition_json);
}

static void rule_copy(dpolicy_rule_t *dst, const dpolicy_rule_t *src)
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

static void version_free(dpolicy_version_t *v)
{
    if (!v)
        return;
    for (size_t i = 0; i < v->rule_count; i++)
        rule_free(&v->rules[i]);
    AIRY_FREE(v->rules);
    AIRY_FREE(v->created_by);
    AIRY_FREE(v->description);
    __builtin_memset(v, 0, sizeof(*v));
}

/* 深拷贝当前规则到版本快照 */
static int version_snapshot(dpolicy_engine_t *e, dpolicy_version_t *v, const char *desc,
                            const char *by)
{
    __builtin_memset(v, 0, sizeof(*v));
    if (e->rule_count > 0) {
        v->rules = AIRY_CALLOC(e->rule_count, sizeof(dpolicy_rule_t));
        if (!v->rules)
            return -1;
        for (size_t i = 0; i < e->rule_count; i++) {
            rule_copy(&v->rules[i], &e->rules[i]);
            if ((e->rules[i].condition_json && e->rules[i].condition_json[0]) &&
                !v->rules[i].condition_json) {
                version_free(v);
                return -1;
            }
        }
    }
    v->rule_count = e->rule_count;
    v->created_at = now_ms();
    if (desc && desc[0])
        v->description = AIRY_STRDUP(desc);
    if (by && by[0])
        v->created_by = AIRY_STRDUP(by);
    return 0;
}

static void fire_change(dpolicy_engine_t *e, dpolicy_change_type_t type, const char *rule_id,
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
    rec.timestamp = now_ms();
    rec.changed_by = (char *)(by ? by : "");
    e->cb(&rec, e->cb_ud);
}

/* 规则是否命中（glob + 时间窗口 + enabled） */
static int rule_matches(const dpolicy_rule_t *r, const char *subject, const char *action,
                        const char *resource)
{
    if (!r->enabled)
        return 0;
    if (r->valid_from > 0 && now_ms() < r->valid_from)
        return 0;
    if (r->valid_until > 0 && now_ms() > r->valid_until)
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
        rule_free(&engine->rules[i]);
    AIRY_FREE(engine->rules);
    for (size_t i = 0; i < engine->version_count; i++)
        version_free(&engine->versions[i]);
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
        size_t nc = engine->rule_cap * 2;
        dpolicy_rule_t *nr = AIRY_REALLOC(engine->rules, nc * sizeof(dpolicy_rule_t));
        if (!nr) {
            airy_mtx_unlock(&engine->lock);
            return -3;
        }
        engine->rules = nr;
        engine->rule_cap = nc;
    }
    rule_copy(&engine->rules[engine->rule_count], rule);
    if ((rule->condition_json && rule->condition_json[0]) &&
        !engine->rules[engine->rule_count].condition_json) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    engine->rule_count++;
    airy_mtx_unlock(&engine->lock);
    fire_change(engine, DPOLICY_CHANGE_ADD, rule->id, NULL, rule->condition_json,
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
    rule_free(&engine->rules[idx]);
    for (size_t i = (size_t)idx; i + 1 < engine->rule_count; i++)
        engine->rules[i] = engine->rules[i + 1];
    __builtin_memset(&engine->rules[engine->rule_count - 1], 0,
                     sizeof(dpolicy_rule_t));
    engine->rule_count--;
    airy_mtx_unlock(&engine->lock);
    fire_change(engine, DPOLICY_CHANGE_REMOVE, rule_id, NULL, NULL, NULL);
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
    rule_copy(&fresh, new_rule);
    if ((new_rule->condition_json && new_rule->condition_json[0]) &&
        !fresh.condition_json) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    engine->rules[idx] = fresh;
    airy_mtx_unlock(&engine->lock);
    /* fire 在锁外、free old 之前：回调可安全读取 old/new 条件 JSON */
    fire_change(engine, DPOLICY_CHANGE_UPDATE, rule_id, old.condition_json,
                fresh.condition_json, new_rule->name);
    rule_free(&old);
    return 0;
}

/* ── 评估（fail-closed：无匹配默认 DENY） ─────────────────────────── */

dpolicy_effect_t dpolicy_engine_evaluate(dpolicy_engine_t *engine, const char *subject,
                                         const char *action, const char *resource,
                                         const char *context_json)
{
    (void)context_json; /* 条件表达式求值暂未启用，预留扩展槽 */
    if (!engine || !subject || !action || !resource)
        return DPOLICY_EFFECT_DENY;

    airy_mtx_lock(&engine->lock);
    dpolicy_effect_t result = DPOLICY_EFFECT_DENY;
    int matched = 0;
    int best_prio = -1;
    dpolicy_effect_t best_effect = DPOLICY_EFFECT_DENY;
    int has_deny = 0, has_allow = 0, has_cond = 0;

    for (size_t i = 0; i < engine->rule_count; i++) {
        const dpolicy_rule_t *r = &engine->rules[i];
        if (!rule_matches(r, subject, action, resource))
            continue;
        matched = 1;
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

    if (matched) {
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
    airy_mtx_unlock(&engine->lock);
    return result;
}

/* ── 冲突检测与消解 ───────────────────────────────────────────────── */

int dpolicy_engine_detect_conflicts(dpolicy_engine_t *engine, dpolicy_conflict_t **conflicts,
                                    size_t *conflict_count)
{
    if (!engine || !conflicts || !conflict_count)
        return -1;
    airy_mtx_lock(&engine->lock);
    size_t cap = engine->rule_count * engine->rule_count;
    dpolicy_conflict_t *out = AIRY_CALLOC(cap + 1, sizeof(dpolicy_conflict_t));
    if (!out) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    size_t n = 0;
    for (size_t i = 0; i < engine->rule_count && n < DPOLICY_MAX_CONFLICTS; i++) {
        for (size_t j = i + 1; j < engine->rule_count && n < DPOLICY_MAX_CONFLICTS; j++) {
            if (!rules_overlap(&engine->rules[i], &engine->rules[j]))
                continue;
            AIRY_STRNCPY_TERM(out[n].rule_a_id, engine->rules[i].id, sizeof(out[n].rule_a_id));
            AIRY_STRNCPY_TERM(out[n].rule_b_id, engine->rules[j].id, sizeof(out[n].rule_b_id));
            out[n].resolution = engine->strategy;
            snprintf(out[n].reason, sizeof(out[n].reason),
                     "overlapping scope with divergent effects");
            n++;
        }
    }
    airy_mtx_unlock(&engine->lock);
    *conflicts = out;
    *conflict_count = n;
    return 0;
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

/* ── 版本管理（epoch SSoT） ───────────────────────────────────────── */

int dpolicy_engine_commit_version(dpolicy_engine_t *engine, const char *description)
{
    if (!engine)
        return -1;
    airy_mtx_lock(&engine->lock);
    if (engine->version_count >= DPOLICY_MAX_VERSIONS) {
        /* 超出 32 版：丢弃最旧，保留最近 31 + 新 1 */
        version_free(&engine->versions[0]);
        for (size_t i = 1; i < engine->version_count; i++)
            engine->versions[i - 1] = engine->versions[i];
        engine->version_count--;
    }
    dpolicy_version_t v;
    if (version_snapshot(engine, &v, description, NULL) != 0) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    char vtag[32];
    snprintf(vtag, sizeof(vtag), "v%llu", (unsigned long long)(engine->epoch + 1));
    AIRY_STRNCPY_TERM(v.version, vtag, sizeof(v.version));
    engine->versions[engine->version_count++] = v;
    engine->epoch++;
    airy_mtx_unlock(&engine->lock);
    fire_change(engine, DPOLICY_CHANGE_COMMIT, NULL, NULL, NULL, description);
    return 0;
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
        rule_free(&engine->rules[i]);
    __builtin_memset(engine->rules, 0, engine->rule_cap * sizeof(dpolicy_rule_t));
    engine->rule_count = 0;
    for (size_t i = 0; i < target->rule_count; i++) {
        rule_copy(&engine->rules[i], &target->rules[i]);
        if ((target->rules[i].condition_json && target->rules[i].condition_json[0]) &&
            !engine->rules[i].condition_json) {
            airy_mtx_unlock(&engine->lock);
            return -3;
        }
    }
    engine->rule_count = target->rule_count;
    engine->epoch++;
    airy_mtx_unlock(&engine->lock);
    fire_change(engine, DPOLICY_CHANGE_ROLLBACK, NULL, NULL, NULL, version);
    return 0;
}

/* ── JSON 导入导出 ────────────────────────────────────────────────── */

/* 锁内清空规则集（load 整体替换用） */
static void clear_rules_locked(dpolicy_engine_t *e)
{
    for (size_t i = 0; i < e->rule_count; i++)
        rule_free(&e->rules[i]);
    __builtin_memset(e->rules, 0, e->rule_cap * sizeof(dpolicy_rule_t));
    e->rule_count = 0;
}

static int rule_from_json(dpolicy_engine_t *e, cJSON *j)
{
    dpolicy_rule_t r;
    __builtin_memset(&r, 0, sizeof(r));
    cJSON *v;
    v = cJSON_GetObjectItem(j, "id");
    if (cJSON_IsString(v) && v->valuestring && v->valuestring[0])
        AIRY_STRNCPY_TERM(r.id, v->valuestring, sizeof(r.id));
    else
        return -1;
    v = cJSON_GetObjectItem(j, "name");
    if (cJSON_IsString(v))
        AIRY_STRNCPY_TERM(r.name, v->valuestring, sizeof(r.name));
    v = cJSON_GetObjectItem(j, "effect");
    if (cJSON_IsString(v)) {
        if (strcmp(v->valuestring, "allow") == 0)
            r.effect = DPOLICY_EFFECT_ALLOW;
        else if (strcmp(v->valuestring, "deny") == 0)
            r.effect = DPOLICY_EFFECT_DENY;
        else if (strcmp(v->valuestring, "conditional") == 0)
            r.effect = DPOLICY_EFFECT_CONDITIONAL;
        else
            return -1;
    } else if (cJSON_IsNumber(v)) {
        r.effect = (dpolicy_effect_t)v->valueint;
    } else {
        return -1;
    }
    v = cJSON_GetObjectItem(j, "subject");
    if (cJSON_IsString(v))
        AIRY_STRNCPY_TERM(r.subject_pattern, v->valuestring, sizeof(r.subject_pattern));
    else
        AIRY_STRNCPY_TERM(r.subject_pattern, "*", sizeof(r.subject_pattern));
    v = cJSON_GetObjectItem(j, "action");
    if (cJSON_IsString(v))
        AIRY_STRNCPY_TERM(r.action_pattern, v->valuestring, sizeof(r.action_pattern));
    else
        AIRY_STRNCPY_TERM(r.action_pattern, "*", sizeof(r.action_pattern));
    v = cJSON_GetObjectItem(j, "resource");
    if (cJSON_IsString(v))
        AIRY_STRNCPY_TERM(r.resource_pattern, v->valuestring, sizeof(r.resource_pattern));
    else
        AIRY_STRNCPY_TERM(r.resource_pattern, "*", sizeof(r.resource_pattern));
    v = cJSON_GetObjectItem(j, "condition");
    if (cJSON_IsString(v) && v->valuestring && v->valuestring[0])
        r.condition_json = AIRY_STRDUP(v->valuestring);
    v = cJSON_GetObjectItem(j, "priority");
    if (cJSON_IsNumber(v))
        r.priority = (safety_priority_t)v->valueint;
    v = cJSON_GetObjectItem(j, "enabled");
    if (cJSON_IsBool(v))
        r.enabled = cJSON_IsTrue(v) ? 1 : 0;
    else
        r.enabled = 1;
    int rc = dpolicy_engine_add_rule(e, &r) == 0 ? 0 : -1;
    AIRY_FREE(r.condition_json); /* add_rule 内已深拷贝，栈临时指针即刻释放 */
    return rc;
}

int dpolicy_engine_load_policies_json(dpolicy_engine_t *engine, const char *json)
{
    if (!engine || !json)
        return -1;
    cJSON *root = cJSON_Parse(json);
    if (!root)
        return -1;
    cJSON *rules = cJSON_GetObjectItem(root, "rules");
    if (!cJSON_IsArray(rules)) {
        cJSON_Delete(root);
        return -2;
    }
    /* 整体替换语义：先清空现有规则集，再逐条导入（load 幂等） */
    airy_mtx_lock(&engine->lock);
    clear_rules_locked(engine);
    airy_mtx_unlock(&engine->lock);
    int rc = 0;
    int n = cJSON_GetArraySize(rules);
    for (int i = 0; i < n; i++) {
        cJSON *r = cJSON_GetArrayItem(rules, i);
        if (cJSON_IsObject(r)) {
            if (rule_from_json(engine, r) != 0)
                rc = -2;
        }
    }
    cJSON_Delete(root);
    return rc;
}

int dpolicy_engine_export_policies_json(dpolicy_engine_t *engine, char **json)
{
    if (!engine || !json)
        return -1;
    airy_mtx_lock(&engine->lock);
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        airy_mtx_unlock(&engine->lock);
        return -3;
    }
    cJSON_AddNumberToObject(root, "epoch", (double)engine->epoch);
    cJSON_AddNumberToObject(root, "version_count", (double)engine->version_count);
    cJSON_AddNumberToObject(root, "rule_count", (double)engine->rule_count);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < engine->rule_count; i++) {
        const dpolicy_rule_t *r = &engine->rules[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "id", r->id);
        cJSON_AddStringToObject(o, "name", r->name);
        const char *eff = r->effect == DPOLICY_EFFECT_ALLOW  ? "allow" :
                          r->effect == DPOLICY_EFFECT_DENY   ? "deny" :
                                                               "conditional";
        cJSON_AddStringToObject(o, "effect", eff);
        cJSON_AddStringToObject(o, "subject", r->subject_pattern);
        cJSON_AddStringToObject(o, "action", r->action_pattern);
        cJSON_AddStringToObject(o, "resource", r->resource_pattern);
        if (r->condition_json)
            cJSON_AddStringToObject(o, "condition", r->condition_json);
        cJSON_AddNumberToObject(o, "priority", r->priority);
        cJSON_AddBoolToObject(o, "enabled", r->enabled ? 1 : 0);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "rules", arr);
    airy_mtx_unlock(&engine->lock);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out)
        return -3;
    *json = out;
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
