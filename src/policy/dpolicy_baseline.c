// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file dpolicy_baseline.c
 * @brief Dynamic Policy Engine 策略基线（YAML）单点导入。
 *
 * 基线是 PDP 运行集的启动形态：进程启动时一次性读入
 * `<config>/cupolas/policy_baseline.yaml`，转换为规则文档后经
 * dpolicy_engine_load_policies_json 原子替换运行集；此后 policy.load /
 * policy.activate 仍以运行集为唯一裁决来源，不存在并行的第二真相源。
 *
 * 语义：文件缺席 = 未配置基线（不导入）；文件存在但解析失败、规则非法
 * 或 id 重复 = 整体失败，运行集保持原状，由宿主拒启（fail-closed）。
 */

#include "airy_memory.h"
#include "dpolicy_internal.h"
#include "yaml_minimal.h"

#include <cjson/cJSON.h>

#include <string.h>

/* 基线文档两形态归一：顶层序列，或 {"rules": [...]} 映射。 */
static struct yaml_node *baseline_rules(struct yaml_node *root)
{
    if (!root)
        return NULL;
    if (root->type == YAML_NODE_SEQUENCE)
        return root;
    struct yaml_node *rules = yaml_get(root, "rules");
    return (rules && rules->type == YAML_NODE_SEQUENCE) ? rules : NULL;
}

/* 基线 effect 只接受三种语义名（数字形态留给运行期 JSON 导入）。 */
static const char *baseline_effect(struct yaml_node *entry)
{
    const char *eff = yaml_as_string(yaml_get(entry, "effect"), NULL);
    if (!eff)
        return NULL;
    if (strcmp(eff, "allow") != 0 && strcmp(eff, "deny") != 0 &&
        strcmp(eff, "conditional") != 0)
        return NULL;
    return eff;
}

/* 可选标量字段：缺省或非标量时按 dflt 处理（NULL 表示不落键）。 */
static void baseline_put_str(cJSON *o, struct yaml_node *entry, const char *key,
                             const char *dflt)
{
    const char *v = yaml_as_string(yaml_get(entry, key), dflt);
    if (v)
        cJSON_AddStringToObject(o, key, v);
}

/* 单条基线规则 → cJSON 规则对象；缺 id 或 effect 非法返回 NULL。 */
static cJSON *baseline_entry(struct yaml_node *entry)
{
    const char *id = yaml_as_string(yaml_get(entry, "id"), NULL);
    const char *effect = baseline_effect(entry);
    if (!id || !id[0] || !effect)
        return NULL;
    cJSON *o = cJSON_CreateObject();
    if (!o)
        return NULL;
    cJSON_AddStringToObject(o, "id", id);
    cJSON_AddStringToObject(o, "effect", effect);
    baseline_put_str(o, entry, "name", NULL);
    baseline_put_str(o, entry, "subject", "*");
    baseline_put_str(o, entry, "action", "*");
    baseline_put_str(o, entry, "resource", "*");
    baseline_put_str(o, entry, "condition", NULL);
    if (yaml_has_key(entry, "priority"))
        cJSON_AddNumberToObject(o, "priority",
                                (double)yaml_as_int64(yaml_get(entry, "priority"), 0));
    if (yaml_has_key(entry, "enabled"))
        cJSON_AddBoolToObject(o, "enabled",
                              yaml_as_bool(yaml_get(entry, "enabled"), true) ? 1 : 0);
    return o;
}

/* 文档树 → JSON 文本。任一条非法即整体失败；成功输出由 cJSON 分配。 */
static int baseline_to_json(struct yaml_node *root, char **out)
{
    struct yaml_node *rules = baseline_rules(root);
    if (!rules)
        return -2;
    cJSON *doc = cJSON_CreateObject();
    if (!doc)
        return -1;
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        cJSON_Delete(doc);
        return -1;
    }
    size_t n = yaml_size(rules);
    for (size_t i = 0; i < n; i++) {
        struct yaml_node *entry = yaml_get_index(rules, i);
        cJSON *o = (entry && entry->type == YAML_NODE_MAPPING) ? baseline_entry(entry) : NULL;
        if (!o) {
            cJSON_Delete(arr);
            cJSON_Delete(doc);
            return -2;
        }
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(doc, "rules", arr);
    char *json = cJSON_PrintUnformatted(doc);
    cJSON_Delete(doc);
    if (!json)
        return -1;
    *out = json;
    return 0;
}

int dpolicy_base_load(dpolicy_engine_t *engine, const char *path)
{
    if (!engine || !path)
        return -1;
    yaml_document_t *doc = yaml_create();
    if (!doc)
        return -1;
    int rc;
    if (yaml_parse_file(doc, path) != 0) {
        rc = -1;
    } else {
        char *json = NULL;
        rc = baseline_to_json(yaml_root(doc), &json);
        if (rc == 0) {
            rc = dpolicy_engine_load_policies_json(engine, json);
            cJSON_free(json);
        }
    }
    yaml_destroy(doc);
    return rc;
}
