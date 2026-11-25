// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 * test_dpolicy_baseline.c - 策略基线（YAML）单点导入
 *
 * 覆盖：映射/序列两形态、字段映射与默认值、可评估性、缺失 id/未知 effect/
 * 重复 id/缺文件整体失败且运行集保持原状（事务式）。
 */

#include "dynamic_policy_engine.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define TEST_PASS(name) printf("[PASS] %s\n", name)
#define TEST_FAIL(name, msg) printf("[FAIL] %s: %s\n", name, msg)

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) {                                                        \
            s_pass++;                                                      \
        } else {                                                           \
            s_fail++;                                                      \
            TEST_FAIL(__func__, #cond);                                    \
        }                                                                  \
    } while (0)

static int s_pass = 0;
static int s_fail = 0;

static const char *s_dir = AIRY_TMP_DIR "/cupolas_policy_baseline";

static void t_mkdir(void)
{
#if defined(_WIN32)
    (void)_mkdir(s_dir);
#else
    (void)mkdir(s_dir, 0755);
#endif
}

static void t_write(const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", s_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

static void t_path(char *buf, size_t size, const char *name)
{
    snprintf(buf, size, "%s/%s", s_dir, name);
}

static const char *k_valid =
    "rules:\n"
    "  - id: allow-read\n"
    "    name: 只读放行\n"
    "    effect: allow\n"
    "    action: read\n"
    "    priority: 10\n"
    "  - id: deny-write\n"
    "    effect: deny\n"
    "    action: write\n"
    "    enabled: false\n";

/* 基线导入后规则可参与裁决，且未在基线中声明的维度取通配。 */
static void t_valid(void)
{
    char path[512];
    t_path(path, sizeof(path), "valid.yaml");
    t_write("valid.yaml", k_valid);
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(e != NULL);
    CHECK(dpolicy_base_load(e, path) == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 2);
    CHECK(dpolicy_engine_evaluate(e, "user:alice", "read", "file:/a", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    /* enabled: false 的规则不参与裁决 → 无命中回退 deny-all */
    CHECK(dpolicy_engine_evaluate(e, "user:alice", "write", "file:/a", NULL) ==
          DPOLICY_EFFECT_DENY);
    dpolicy_engine_destroy(e);
    TEST_PASS("valid");
}

/* 顶层直接为序列同样可导入。 */
static void t_sequence(void)
{
    char path[512];
    t_path(path, sizeof(path), "seq.yaml");
    t_write("seq.yaml",
            "- id: all-allow\n"
            "  effect: allow\n"
            "  subject: \"*\"\n"
            "  action: \"*\"\n"
            "  resource: \"*\"\n");
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_base_load(e, path) == 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 1);
    CHECK(dpolicy_engine_evaluate(e, "anyone", "deploy", "svc:a", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    dpolicy_engine_destroy(e);
    TEST_PASS("sequence");
}

/* 非法基线整体失败，运行集保持导入前状态（先以合法基线打底）。 */
static void t_reject(const char *name, const char *body)
{
    char good[512];
    char bad[512];
    t_path(good, sizeof(good), "valid.yaml");
    t_path(bad, sizeof(bad), name);
    t_write(name, body);
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_base_load(e, good) == 0);
    size_t before = dpolicy_engine_get_rule_count(e);
    CHECK(before == 2);
    CHECK(dpolicy_base_load(e, bad) < 0);
    CHECK(dpolicy_engine_get_rule_count(e) == before);
    CHECK(dpolicy_engine_evaluate(e, "user:alice", "read", "file:/a", NULL) ==
          DPOLICY_EFFECT_ALLOW);
    dpolicy_engine_destroy(e);
    remove(bad);
}

static void t_rejects(void)
{
    t_reject("no-id.yaml",
             "rules:\n"
             "  - effect: allow\n"
             "    action: read\n");
    t_reject("bad-effect.yaml",
             "rules:\n"
             "  - id: r1\n"
             "    effect: maybe\n");
    t_reject("dup-id.yaml",
             "rules:\n"
             "  - id: r1\n"
             "    effect: allow\n"
             "  - id: r1\n"
             "    effect: deny\n");
    t_reject("not-mapping.yaml",
             "rules:\n"
             "  - 42\n");
    t_reject("no-rules.yaml", "name: empty\n");
    TEST_PASS("rejects");
}

/* 文件缺席返回失败；调用方据此区分“未配置”与“配置非法”。 */
static void t_missing(void)
{
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_base_load(e, AIRY_TMP_DIR "/cupolas_policy_baseline/none.yaml") < 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 0);
    dpolicy_engine_destroy(e);
    TEST_PASS("missing");
}

int main(void)
{
    t_mkdir();
    t_valid();
    t_sequence();
    t_rejects();
    t_missing();
    char path[512];
    t_path(path, sizeof(path), "valid.yaml");
    remove(path);
    t_path(path, sizeof(path), "seq.yaml");
    remove(path);
    printf("dpolicy_baseline: %d pass, %d fail\n", s_pass, s_fail);
    return s_fail == 0 ? 0 : 1;
}
