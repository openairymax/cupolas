// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 * test_cupolas_pep_init.c - M2-S5 PEP 最小 guard 初始化单测
 *
 * cupolas_init_pep 不构造本地 permission 引擎（策略由 PDP cupolas_d
 * 唯一持有），sanitizer 层保留。断言：
 *   - pep 初始化成功且可重复调用（幂等 state 机）
 *   - 权限裁定面不可用（引擎缺失 → fail-closed 状态错误，不被误用）
 *   - sanitizer 层仍可用（PEP 本地纯函数变换）
 *   - cupolas_cleanup 对 pep 实例安全
 */

#include "cupolas.h"

#include <stdio.h>
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

int main(void)
{
    /* pep 初始化：本地 permission 引擎不构造 */
    airy_err_t err = AIRY_OK;
    CHECK(cupolas_init_pep(NULL, &err) == CUPOLAS_OK);
    CHECK(cupolas_init_pep(NULL, &err) == CUPOLAS_OK); /* 幂等 */

    /* 权限裁定面不可用：引擎缺失 → 状态错误（fail-closed），
     * 防止 pep 进程本地误判（策略必须经 PDP） */
    CHECK(cupolas_check_permission("agent-1", "execute", "tool.x", NULL) < 0);

    /* sanitizer 层保留：PEP 本地纯函数变换仍可用 */
    char out[256];
    memset(out, 0, sizeof(out));
    int rc = cupolas_sanitize_input("plain text", out, sizeof(out));
    CHECK(rc == CUPOLAS_OK);
    CHECK(out[0] != '\0');

    cupolas_cleanup();
    TEST_PASS("pep_init_semantics");
    printf("cupolas_pep_init: %d pass, %d fail\n", s_pass, s_fail);
    return s_fail == 0 ? 0 : 1;
}
