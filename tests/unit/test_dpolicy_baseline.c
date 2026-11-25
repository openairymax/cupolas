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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static char s_dir[AIRY_PATH_MAX];

/* 夹具根取运行期 SSoT：产品自身经 airy_tmp_dir() 解析临时目录，用例必须
 * 与之同源。编译期 AIRY_TMP_DIR 是机器级常量（Windows 为
 * C:\ProgramData\agentrt\tmp），干净主机上其父目录既不存在也无权创建，
 * 夹具会在建目录处先失败，再沿断言链误报为策略功能缺陷。
 * airy_mkdir_p() 逐级创建并回传失败，避免「父目录缺失 → 写入静默失败」。 */
static int t_mkdir(void)
{
    snprintf(s_dir, sizeof(s_dir), "%s/%s", airy_tmp_dir(), "cupolas_policy_baseline");
    if (airy_mkdir_p(s_dir) != 0) {
        printf("mkdir failed: %s (errno=%d %s)\n", s_dir, errno, strerror(errno));
        return -1;
    }
    return 0;
}

static int t_write(const char *name, const char *text)
{
    char path[AIRY_PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/%s", s_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    size_t n = fwrite(text, 1, strlen(text), f);
    int closed = fclose(f);
    return (n == strlen(text) && closed == 0) ? 0 : -1;
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
    char path[AIRY_PATH_MAX + 64];
    t_path(path, sizeof(path), "valid.yaml");
    CHECK(t_write("valid.yaml", k_valid) == 0);
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
    char path[AIRY_PATH_MAX + 64];
    t_path(path, sizeof(path), "seq.yaml");
    CHECK(t_write("seq.yaml",
                  "- id: all-allow\n"
                  "  effect: allow\n"
                  "  subject: \"*\"\n"
                  "  action: \"*\"\n"
                  "  resource: \"*\"\n") == 0);
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
    char good[AIRY_PATH_MAX + 64];
    char bad[AIRY_PATH_MAX + 64];
    t_path(good, sizeof(good), "valid.yaml");
    t_path(bad, sizeof(bad), name);
    CHECK(t_write(name, body) == 0);
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
    char path[AIRY_PATH_MAX + 64];
    t_path(path, sizeof(path), "none.yaml");
    dpolicy_engine_t *e = dpolicy_engine_create(DPOLICY_CONFLICT_DENY_WINS);
    CHECK(dpolicy_base_load(e, path) < 0);
    CHECK(dpolicy_engine_get_rule_count(e) == 0);
    dpolicy_engine_destroy(e);
    TEST_PASS("missing");
}

int main(void)
{
    /* 输出不缓冲：用例被杀（超时）时仍能看到最后一条进度，便于定位挂起点。 */
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(t_mkdir() == 0);
    t_valid();
    t_sequence();
    t_rejects();
    t_missing();
    char path[AIRY_PATH_MAX + 64];
    t_path(path, sizeof(path), "valid.yaml");
    remove(path);
    t_path(path, sizeof(path), "seq.yaml");
    remove(path);
    printf("dpolicy_baseline: %d pass, %d fail\n", s_pass, s_fail);
    return s_fail == 0 ? 0 : 1;
}
