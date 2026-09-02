// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 * test_dynamic_policy_engine.c - M2-S2 DP 引擎单元测试
 *
 * 覆盖：规则增删改 / glob 匹配 / fail-closed / 冲突消解 4 策略 /
 * 版本 commit-rollback / 32 版上限 / JSON 往返 / 合规兜底 deny-all /
 * 变更回调。
 */

#include "dynamic_policy_engine.h"

#include <cjson/cJSON.h>

#include "airy_memory.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASS(name) printf("[PASS] %s\n", name)
#define TEST_FAIL(name, msg) printf("[FAIL] %s: %s\n", name, msg)

static int s_pass = 0;
static int s_fail = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) {                                                        \
            s_pass++;                                                      \
        } else {                                                           \
            s_fail++;                                                      \
            TEST_FAIL(__func__, #cond);                                    \
        }                                                                  \
    } while (0)

static void t_lifecycle(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(e != NULL);
    dpolicy_engine_destroy(e);
    dpolicy_engine_destroy(NULL);
    TEST_PASS("lifecycle");
}

static void t_add_remove(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "r1");
    strcpy(r.name, "deny tool exec");
    r.effect = DPOLICY_EFFECT_DENY;
    strcpy(r.subject_pattern, "agent-*");
    strcpy(r.action_pattern, "tool.exec");
    strcpy(r.resource_pattern, "*");
    r.priority = SAFETY_PRIORITY_NORMAL;
    r.enabled = true;

    CHECK(dpolicy_engine_add_rule(e, &r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &r) == -2); /* 重复 id 拒绝 */
    CHECK(dpolicy_engine_get_rule_count(e) == 1);

    dpolicy_rule_t bad;
    memset(&bad, 0, sizeof(bad)); /* 空 id 拒绝 */
    CHECK(dpolicy_engine_add_rule(e, &bad) == -1);

    CHECK(dpolicy_engine_remove_rule(e, "r1") == 0);
    CHECK(dpolicy_engine_remove_rule(e, "r1") == -2); /* 已删除 */
    CHECK(dpolicy_engine_get_rule_count(e) == 0);

    dpolicy_engine_destroy(e);
    TEST_PASS("add_remove");
}

static void t_failclosed(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_engine_evaluate(e, "a", "b", "c", NULL) == DPOLICY_EFFECT_DENY);
    CHECK(dpolicy_engine_evaluate(NULL, "a", "b", "c", NULL) == DPOLICY_EFFECT_DENY);
    CHECK(dpolicy_engine_evaluate(e, NULL, "b", "c", NULL) == DPOLICY_EFFECT_DENY);
    dpolicy_engine_destroy(e);
    TEST_PASS("fail_closed");
}

static void t_glob(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "g1");
    r.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(r.subject_pattern, "agent-*");
    strcpy(r.action_pattern, "tool.*");
    r.enabled = true;

    CHECK(dpolicy_engine_add_rule(e, &r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "agent-1", "tool.exec", "file", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(dpolicy_engine_evaluate(e, "tool-1", "tool.exec", "file", NULL) ==
          DPOLICY_EFFECT_DENY); /* subject 不匹配 */
    CHECK(dpolicy_engine_evaluate(e, "agent-1", "llm.chat", "file", NULL) ==
          DPOLICY_EFFECT_DENY); /* action 不匹配 */

    /* enabled=false 门控：禁用 g1 后无匹配 → fail-closed DENY */
    r.enabled = false;
    strcpy(r.id, "g1");
    CHECK(dpolicy_engine_update_rule(e, "g1", &r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "agent-1", "tool.exec", "file", NULL) ==
          DPOLICY_EFFECT_DENY);

    dpolicy_engine_destroy(e);
    TEST_PASS("glob");
}

static void t_strategies(void)
{
    dpolicy_rule_t allow_r, deny_r;
    memset(&allow_r, 0, sizeof(allow_r));
    memset(&deny_r, 0, sizeof(deny_r));
    strcpy(allow_r.id, "a1");
    allow_r.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(allow_r.subject_pattern, "*");
    strcpy(allow_r.action_pattern, "tool.exec");
    allow_r.priority = SAFETY_PRIORITY_LOW;
    allow_r.enabled = true;
    strcpy(deny_r.id, "d1");
    deny_r.effect = DPOLICY_EFFECT_DENY;
    strcpy(deny_r.subject_pattern, "*");
    strcpy(deny_r.action_pattern, "tool.exec");
    deny_r.priority = SAFETY_PRIORITY_HIGH;
    deny_r.enabled = true;

    /* DENY_WINS */
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_engine_add_rule(e, &allow_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &deny_r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_DENY);
    dpolicy_engine_destroy(e);

    /* ALLOW_WINS */
    e = dpolicy_engine_create(DPOLICY_CONFLICT_ALLOW_WINS);
    CHECK(dpolicy_engine_add_rule(e, &allow_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &deny_r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    dpolicy_engine_destroy(e);

    /* HIGHEST_PRIORITY：deny 高优先级胜出 */
    e = dpolicy_engine_create(DPOLICY_CONFLICT_HIGHEST_PRIORITY);
    CHECK(dpolicy_engine_add_rule(e, &allow_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &deny_r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_DENY);
    dpolicy_engine_destroy(e);

    /* MOST_RESTRICTIVE */
    e = dpolicy_engine_create(DPOLICY_CONFLICT_MOST_RESTRICTIVE);
    CHECK(dpolicy_engine_add_rule(e, &allow_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &deny_r) == 0);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_DENY);
    dpolicy_engine_destroy(e);

    TEST_PASS("strategies");
}

static void t_detect(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    dpolicy_rule_t allow_r, deny_r, allow_r2;
    memset(&allow_r, 0, sizeof(allow_r));
    memset(&deny_r, 0, sizeof(deny_r));
    memset(&allow_r2, 0, sizeof(allow_r2));

    strcpy(allow_r.id, "a1");
    allow_r.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(allow_r.action_pattern, "tool.exec");
    allow_r.enabled = true;
    strcpy(deny_r.id, "d1");
    deny_r.effect = DPOLICY_EFFECT_DENY;
    strcpy(deny_r.action_pattern, "tool.exec");
    deny_r.enabled = true;
    strcpy(allow_r2.id, "a2");
    allow_r2.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(allow_r2.action_pattern, "fs.read");
    allow_r2.enabled = true;

    CHECK(dpolicy_engine_add_rule(e, &allow_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &deny_r) == 0);
    CHECK(dpolicy_engine_add_rule(e, &allow_r2) == 0);

    dpolicy_conflict_t *conflicts = NULL;
    size_t n = 0;
    CHECK(dpolicy_engine_detect_conflicts(e, &conflicts, &n) == 0);
    CHECK(n == 1); /* 仅 a1/d1 重叠异效，a2 空间分离 */
    CHECK(conflicts != NULL);
    if (conflicts) {
        CHECK(strcmp(conflicts[0].rule_a_id, "a1") == 0 ||
              strcmp(conflicts[0].rule_b_id, "a1") == 0);
    }
    AIRY_FREE(conflicts);
    dpolicy_engine_destroy(e);
    TEST_PASS("detect_conflicts");
}

static void t_versions(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "v1");
    r.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(r.action_pattern, "tool.exec");
    r.enabled = true;
    CHECK(dpolicy_engine_add_rule(e, &r) == 0);
    CHECK(dpolicy_engine_commit_version(e, "initial") == 0);

    /* 变更规则后 commit 第二版 */
    r.effect = DPOLICY_EFFECT_DENY;
    CHECK(dpolicy_engine_update_rule(e, "v1", &r) == 0);
    CHECK(dpolicy_engine_commit_version(e, "harden") == 0);

    CHECK(dpolicy_engine_get_version_count(e) == 2);
    CHECK(dpolicy_engine_get_rule_count(e) == 1);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_DENY);

    /* 回滚到 v1：effect 恢复 ALLOW */
    CHECK(dpolicy_engine_rollback(e, "v1") == 0);
    CHECK(dpolicy_engine_evaluate(e, "s", "tool.exec", "r", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(dpolicy_engine_rollback(e, "v9") == -2); /* 不存在版本 */

    /* 回滚后 epoch 继续单调递增 */
    CHECK(dpolicy_engine_commit_version(e, "after-rollback") == 0);
    CHECK(dpolicy_engine_get_version_count(e) == 3);

    dpolicy_engine_destroy(e);
    TEST_PASS("versions");
}

static void t_cap32(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    for (int i = 0; i < 40; i++)
        CHECK(dpolicy_engine_commit_version(e, "iter") == 0);
    CHECK(dpolicy_engine_get_version_count(e) == DPOLICY_MAX_VERSIONS);
    CHECK(dpolicy_engine_get_rule_count(e) == 0);
    /* 丢弃最旧后 v9..v40 仍在，可回滚到其中任一 */
    CHECK(dpolicy_engine_rollback(e, "v40") == 0);
    dpolicy_engine_destroy(e);
    TEST_PASS("cap32");
}

static void t_json(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    const char *doc = "{"
                      "\"rules\":["
                      "{\"id\":\"j1\",\"name\":\"allow chat\",\"effect\":\"allow\","
                      "\"subject\":\"agent-*\",\"action\":\"llm.chat\",\"resource\":\"*\","
                      "\"priority\":50,\"enabled\":true},"
                      "{\"id\":\"j2\",\"effect\":\"deny\",\"action\":\"fs.write\","
                      "\"resource\":\"/etc/*\"}"
                      "]}";
    CHECK(dpolicy_engine_load_policies_json(e, doc) == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);
    CHECK(dpolicy_engine_evaluate(e, "agent-1", "llm.chat", "m", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(dpolicy_engine_evaluate(e, "agent-1", "fs.write", "/etc/passwd", NULL) ==
          DPOLICY_EFFECT_DENY);
    CHECK(dpolicy_engine_evaluate(e, "x", "fs.write", "/etc/passwd", NULL) ==
          DPOLICY_EFFECT_DENY); /* subject 无匹配 → fail-closed */

    /* 重复 load 幂等（整体替换） */
    CHECK(dpolicy_engine_load_policies_json(e, doc) == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);

    char *out = NULL;
    CHECK(dpolicy_engine_export_policies_json(e, &out) == 0);
    CHECK(out != NULL);
    CHECK(strstr(out, "\"id\":\"j1\"") != NULL);
    CHECK(strstr(out, "\"effect\":\"deny\"") != NULL);
    cJSON_free(out);

    CHECK(dpolicy_engine_load_policies_json(e, "{\"rules\":[{}]}") == -2);
    CHECK(dpolicy_engine_load_policies_json(e, "not-json") == -1);

    dpolicy_engine_destroy(e);
    TEST_PASS("json");
}

static void t_compliance(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    char *report = NULL;
    /* 无兜底 deny-all → 不合规 */
    CHECK(dpolicy_engine_validate_compliance(e, "fail-closed", &report) == 0);
    CHECK(report != NULL);
    CHECK(strstr(report, "\"pass\":false") != NULL);
    cJSON_free(report);
    report = NULL;

    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "c1");
    r.effect = DPOLICY_EFFECT_DENY;
    strcpy(r.subject_pattern, "*");
    strcpy(r.action_pattern, "*");
    strcpy(r.resource_pattern, "*");
    r.enabled = true;
    CHECK(dpolicy_engine_add_rule(e, &r) == 0);

    CHECK(dpolicy_engine_validate_compliance(e, "fail-closed", &report) == 0);
    CHECK(report != NULL);
    CHECK(strstr(report, "\"pass\":true") != NULL);
    cJSON_free(report);

    dpolicy_engine_destroy(e);
    TEST_PASS("compliance");
}

static int s_cb_add = 0;
static int s_cb_remove = 0;
static int s_cb_commit = 0;

static void on_change(const dpolicy_change_record_t *rec, void *ud)
{
    (void)ud;
    if (!rec)
        return;
    switch (rec->type) {
    case DPOLICY_CHANGE_ADD:
        s_cb_add++;
        break;
    case DPOLICY_CHANGE_REMOVE:
        s_cb_remove++;
        break;
    case DPOLICY_CHANGE_COMMIT:
        s_cb_commit++;
        break;
    default:
        break;
    }
}

static void t_callback(void)
{
    s_cb_add = s_cb_remove = s_cb_commit = 0;
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_engine_set_change_callback(e, on_change, NULL) == 0);

    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "cb1");
    r.effect = DPOLICY_EFFECT_ALLOW;
    r.enabled = true;
    CHECK(dpolicy_engine_add_rule(e, &r) == 0);
    CHECK(s_cb_add == 1);
    CHECK(dpolicy_engine_remove_rule(e, "cb1") == 0);
    CHECK(s_cb_remove == 1);
    CHECK(dpolicy_engine_commit_version(e, "cb") == 0);
    CHECK(s_cb_commit == 1);

    dpolicy_engine_destroy(e);
    TEST_PASS("callback");
}

static void t_eval_match(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    dpolicy_rule_t r;
    memset(&r, 0, sizeof(r));
    strcpy(r.id, "m1");
    r.effect = DPOLICY_EFFECT_ALLOW;
    strcpy(r.subject_pattern, "agent-*");
    strcpy(r.action_pattern, "tool.exec");
    r.enabled = true;

    /* 空集：matched=0 且 fail-closed DENY（供 overlay 回退判定） */
    int matched = -1;
    CHECK(dpolicy_eval_match(e, "s", "a", "r", NULL, &matched) ==
          DPOLICY_EFFECT_DENY);
    CHECK(matched == 0);
    matched = -1;
    CHECK(dpolicy_eval_match(NULL, "s", "a", "r", NULL, &matched) ==
          DPOLICY_EFFECT_DENY);
    CHECK(matched == 0);

    CHECK(dpolicy_engine_add_rule(e, &r) == 0);
    matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "tool.exec", "f", NULL, &matched) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(matched == 1);
    /* action 不匹配：无命中 → DENY + matched=0（区别于显式 DENY） */
    matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "llm.chat", "f", NULL, &matched) ==
          DPOLICY_EFFECT_DENY);
    CHECK(matched == 0);

    dpolicy_engine_destroy(e);
    TEST_PASS("eval_match");
}

static void t_stage_activate(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    /* activate 前置需 load：无暂存拒绝 */
    CHECK(dpolicy_activate(e, "x") == -5);
    CHECK(dpolicy_has_staged(e) == 0);

    const char *doc = "{"
                      "\"rules\":["
                      "{\"id\":\"s1\",\"effect\":\"allow\",\"subject\":\"agent-*\","
                      "\"action\":\"tool.exec\",\"resource\":\"*\",\"enabled\":true}"
                      "]}";
    CHECK(dpolicy_stage_json(e, doc) == 0);
    CHECK(dpolicy_has_staged(e) == 1);
    CHECK(dpolicy_staged_count(e) == 1);
    /* load 不影响运行裁决与 epoch */
    CHECK(dpolicy_engine_get_rule_count(e) == 0);
    CHECK(dpolicy_engine_get_epoch(e) == 0);
    int matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "tool.exec", "f", NULL, &matched) ==
          DPOLICY_EFFECT_DENY);
    CHECK(matched == 0);

    CHECK(dpolicy_activate(e, "v1") == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 1);
    CHECK(dpolicy_engine_get_epoch(e) == 1);
    CHECK(dpolicy_engine_get_version_count(e) == 1);
    CHECK(dpolicy_has_staged(e) == 0);
    CHECK(dpolicy_staged_count(e) == 0);
    matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "tool.exec", "f", NULL, &matched) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(matched == 1);

    /* 显式清空：load 空集 + activate → 运行集归零（回退基础），epoch 单调 */
    CHECK(dpolicy_stage_json(e, "{\"rules\":[]}") == 0);
    CHECK(dpolicy_has_staged(e) == 1);
    CHECK(dpolicy_activate(e, "clear") == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 0);
    CHECK(dpolicy_engine_get_epoch(e) == 2);
    matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "tool.exec", "f", NULL, &matched) ==
          DPOLICY_EFFECT_DENY);
    CHECK(matched == 0);

    /* 回滚 v1（allow 集）恢复规则，epoch 继续单调 */
    CHECK(dpolicy_engine_rollback(e, "v1") == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 1);
    CHECK(dpolicy_engine_get_epoch(e) == 3);
    matched = -1;
    CHECK(dpolicy_eval_match(e, "agent-1", "tool.exec", "f", NULL, &matched) ==
          DPOLICY_EFFECT_ALLOW);
    CHECK(matched == 1);

    dpolicy_engine_destroy(e);
    TEST_PASS("stage_activate");
}

static void t_stage_conflicts(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    const char *doc = "{"
                      "\"rules\":["
                      "{\"id\":\"ca\",\"effect\":\"allow\",\"action\":\"tool.exec\"},"
                      "{\"id\":\"cd\",\"effect\":\"deny\",\"action\":\"tool.exec\"}"
                      "]}";
    CHECK(dpolicy_stage_json(e, doc) == 0);
    CHECK(dpolicy_staged_count(e) == 2);
    /* 冲突报告针对暂存集（load 后、activate 前） */
    dpolicy_conflict_t *conflicts = NULL;
    size_t n = 0;
    CHECK(dpolicy_stage_check(e, &conflicts, &n) == 0);
    CHECK(n == 1);
    AIRY_FREE(conflicts);
    conflicts = NULL;
    /* 运行集未动：live 无冲突 */
    CHECK(dpolicy_engine_detect_conflicts(e, &conflicts, &n) == 0);
    CHECK(n == 0);
    AIRY_FREE(conflicts);

    CHECK(dpolicy_activate(e, "conflict-set") == 0);
    CHECK(dpolicy_engine_detect_conflicts(e, &conflicts, &n) == 0);
    CHECK(n == 1); /* 激活后 deny-wins 生效 */
    AIRY_FREE(conflicts);

    dpolicy_engine_destroy(e);
    TEST_PASS("staged_conflicts");
}

static void t_load_transaction(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    const char *ok = "{"
                     "\"rules\":["
                     "{\"id\":\"t1\",\"effect\":\"allow\",\"action\":\"tool.exec\"},"
                     "{\"id\":\"t2\",\"effect\":\"deny\",\"action\":\"fs.write\"}"
                     "]}";
    CHECK(dpolicy_engine_load_policies_json(e, ok) == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);

    /* 非法文档整体拒绝：目标集保持不动（事务式，非半套应用） */
    CHECK(dpolicy_engine_load_policies_json(e, "{\"rules\":[{\"id\":\"x\"}]}") == -2);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);
    CHECK(dpolicy_engine_load_policies_json(e, "{\"rules\":[{\"id\":\"t1\",\"effect\":\"allow\"},"
                                               "{\"id\":\"t1\",\"effect\":\"deny\"}]}") == -2);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);
    CHECK(dpolicy_engine_load_policies_json(e, "not-json") == -1);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);

    dpolicy_engine_destroy(e);
    TEST_PASS("load_transaction");
}

int main(void)
{
    t_lifecycle();
    t_add_remove();
    t_failclosed();
    t_glob();
    t_strategies();
    t_detect();
    t_versions();
    t_cap32();
    t_json();
    t_compliance();
    t_callback();
    t_eval_match();
    t_stage_activate();
    t_stage_conflicts();
    t_load_transaction();

    printf("dynamic_policy_engine: %d pass, %d fail\n", s_pass, s_fail);
    return s_fail == 0 ? 0 : 1;
}
