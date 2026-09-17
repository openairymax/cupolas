// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dpolicy_json.c
 * @brief Dynamic Policy Engine JSON 导入导出与两段式生效。
 *
 * 文档解析事务式：任一行非法或 id 重复即整体失败，目标集不动。
 * 两段式：policy.load 装载暂存集（运行裁决与 epoch 不变），
 * policy.activate 原子提交运行集 + 版本固化 + epoch+1。
 */

#include "dpolicy_internal.h"

#include <cjson/cJSON.h>

#include <stdio.h>
#include <string.h>

/* ── JSON 解析 ────────────────────────────────────────────────────── */

/* 纯解析：单条规则 JSON → dpolicy_rule_t（condition_json 深拷贝） */
static int rule_from_json(const cJSON *j, dpolicy_rule_t *out)
{
    dpolicy_rule_t r;
    __builtin_memset(&r, 0, sizeof(r));
    const cJSON *v;
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
    *out = r;
    return 0;
}

/* 规则集容器（文档解析目标：先于引擎锁完整构建，再整体迁移，事务式） */
typedef struct {
    dpolicy_rule_t *items;
    size_t count;
    size_t cap;
} rule_array_t;

static void rule_array_free(rule_array_t *a)
{
    if (!a)
        return;
    for (size_t i = 0; i < a->count; i++)
        dpol_rule_free(&a->items[i]);
    AIRY_FREE(a->items);
    __builtin_memset(a, 0, sizeof(*a));
}

static int rule_array_append(rule_array_t *a, const dpolicy_rule_t *r)
{
    if (!a || !r)
        return -1;
    if (a->count >= a->cap) {
        size_t nc = a->cap > 0 ? a->cap * 2 : 8;
        dpolicy_rule_t *ni = AIRY_REALLOC(a->items, nc * sizeof(dpolicy_rule_t));
        if (!ni)
            return -3;
        a->items = ni;
        a->cap = nc;
    }
    dpol_rule_copy(&a->items[a->count], r);
    if ((r->condition_json && r->condition_json[0]) && !a->items[a->count].condition_json)
        return -3;
    a->count++;
    return 0;
}

/* 解析策略文档 → 规则数组。事务式：任一行非法或 id 重复即整体失败（-2），
 * 目标集保持不动——杜绝“半套应用后拒绝”的撕裂状态（load/stage 共用）。 */
static int doc_to_array(const char *json, rule_array_t *out)
{
    if (!json || !out)
        return -1;
    cJSON *root = cJSON_Parse(json);
    if (!root)
        return -1;
    const cJSON *rules = cJSON_GetObjectItem(root, "rules");
    if (!cJSON_IsArray(rules)) {
        cJSON_Delete(root);
        return -2;
    }
    rule_array_t tmp = {0};
    int rc = 0;
    int n = cJSON_GetArraySize(rules);
    for (int i = 0; i < n; i++) {
        const cJSON *r = cJSON_GetArrayItem(rules, i);
        if (!cJSON_IsObject(r)) {
            rc = -2;
            break;
        }
        dpolicy_rule_t parsed;
        if (rule_from_json(r, &parsed) != 0) {
            rc = -2;
            break;
        }
        for (size_t k = 0; k < tmp.count; k++) {
            if (strcmp(tmp.items[k].id, parsed.id) == 0) {
                AIRY_FREE(parsed.condition_json);
                rc = -2;
                break;
            }
        }
        if (rc == 0) {
            if (rule_array_append(&tmp, &parsed) != 0)
                rc = -3;
            AIRY_FREE(parsed.condition_json); /* append 已深拷贝 */
        }
        if (rc != 0)
            break;
    }
    cJSON_Delete(root);
    if (rc != 0) {
        rule_array_free(&tmp);
        return rc;
    }
    *out = tmp;
    return 0;
}

/* ── 运行集替换与装载 ─────────────────────────────────────────────── */

/* 锁内以 src 整体替换运行集（迁移所有权）。始终保证 rules 非 NULL 且
 * cap>=8：activate(空暂存) 清空运行集后 add_rule 仍可直接写入。 */
static void live_replace_locked(dpolicy_engine_t *e, rule_array_t *src)
{
    for (size_t i = 0; i < e->rule_count; i++)
        dpol_rule_free(&e->rules[i]);
    AIRY_FREE(e->rules);
    e->rules = src->items;
    e->rule_count = src->count;
    e->rule_cap = src->cap > 0 ? src->cap : 8;
    if (src->cap == 0)
        e->rules = AIRY_CALLOC(e->rule_cap, sizeof(dpolicy_rule_t));
    src->items = NULL;
    src->count = src->cap = 0;
}

int dpolicy_engine_load_policies_json(dpolicy_engine_t *engine, const char *json)
{
    if (!engine || !json)
        return -1;
    rule_array_t doc;
    __builtin_memset(&doc, 0, sizeof(doc));
    int rc = doc_to_array(json, &doc);
    if (rc != 0)
        return rc;
    airy_mtx_lock(&engine->lock);
    live_replace_locked(engine, &doc);
    airy_mtx_unlock(&engine->lock);
    return 0;
}

/* 两段式生效：policy.load 仅装载入暂存集——运行
 * 裁决与 epoch 不变，冲突报告针对暂存文档；activate 才原子提交运行集并
 * 版本固化 + epoch+1（PEP 缓存失效键由此单调推进）。 */
int dpolicy_stage_json(dpolicy_engine_t *engine, const char *json)
{
    if (!engine || !json)
        return -1;
    rule_array_t doc;
    __builtin_memset(&doc, 0, sizeof(doc));
    int rc = doc_to_array(json, &doc);
    if (rc != 0)
        return rc;
    airy_mtx_lock(&engine->lock);
    for (size_t i = 0; i < engine->staged_count; i++)
        dpol_rule_free(&engine->staged[i]);
    AIRY_FREE(engine->staged);
    engine->staged = doc.items;
    engine->staged_count = doc.count;
    engine->staged_cap = doc.cap;
    doc.items = NULL;
    doc.count = doc.cap = 0;
    engine->staged_valid = 1;
    airy_mtx_unlock(&engine->lock);
    return 0;
}

int dpolicy_activate(dpolicy_engine_t *engine, const char *description)
{
    if (!engine)
        return -1;
    airy_mtx_lock(&engine->lock);
    if (!engine->staged_valid) {
        airy_mtx_unlock(&engine->lock);
        return -5; /* 无暂存文档：policy.activate 前置需 policy.load */
    }
    /* 暂存 → 运行原子提交（同一临界区，evaluate 观察不到撕裂状态） */
    rule_array_t staged_doc = {.items = engine->staged, .count = engine->staged_count,
                               .cap = engine->staged_cap};
    engine->staged = NULL;
    engine->staged_count = engine->staged_cap = 0;
    engine->staged_valid = 0;
    live_replace_locked(engine, &staged_doc);
    int rc = dpol_commit_locked(engine, description);
    airy_mtx_unlock(&engine->lock);
    if (rc == 0)
        dpol_fire_change(engine, DPOLICY_CHANGE_COMMIT, NULL, NULL, NULL, description);
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
