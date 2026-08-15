// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file test_sandbox.c
 * @brief cupolas_sandbox 单元测试（S-7：Landlock + seccomp）
 *
 * 验证：
 * - cupolas_sandbox_init: 清零为禁用默认
 * - cupolas_sandbox_apply: NULL / disabled 为零开销 no-op
 * - enabled 沙箱：命令在 Landlock 默认只读 + rw_paths 下正常执行
 * - 写限制：rw_paths 内可写、外部只读路径写入被拒（Linux 内核支持时）
 * - deny_network：网络 syscall 被 seccomp 拦截（Linux 内核支持时）
 *
 * 内核不支持 Landlock（< 5.13）或头文件缺失时，enabled 用例自动
 * SKIP（apply 返回非 0），不误报失败。
 */

#include "platform/sandbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static int g_tests_passed = 0;
static int g_tests_failed = 0;
static int g_tests_skipped = 0;

#define TEST_PASS(name)                \
    do {                               \
        g_tests_passed++;              \
        printf("  [PASS] %s\n", name); \
    } while (0)

#define TEST_SKIP(name, why)                              \
    do {                                                  \
        g_tests_skipped++;                                \
        printf("  [SKIP] %s — %s\n", name, why);          \
    } while (0)

#define TEST_FAIL(name, msg)                                         \
    do {                                                             \
        g_tests_failed++;                                            \
        printf("  [FAIL] %s — %s (line %d)\n", name, msg, __LINE__); \
    } while (0)

#define TEST_ASSERT(cond, name, msg) \
    do {                             \
        if (!(cond)) {               \
            TEST_FAIL(name, msg);    \
            return;                  \
        }                            \
    } while (0)

#define RUN_TEST(func)                 \
    do {                               \
        printf("--- %s ---\n", #func); \
        func();                        \
    } while (0)

static void test_sandbox_init(void)
{
    cupolas_sandbox_t sb;
    cupolas_sandbox_init(&sb);
    TEST_ASSERT(sb.enabled == 0, "init clears enabled", "not zero");
    TEST_ASSERT(sb.deny_network == 0, "init clears deny_network", "not zero");
    TEST_ASSERT(sb.ro_paths == NULL, "init clears ro_paths", "not NULL");
    TEST_ASSERT(sb.rw_paths == NULL, "init clears rw_paths", "not NULL");
    TEST_PASS("sandbox_init zeroes the config (disabled default)");
}

static void test_sandbox_noop(void)
{
    TEST_ASSERT(cupolas_sandbox_apply(NULL) == 0, "apply(NULL) is no-op", "failed");
    cupolas_sandbox_t sb;
    cupolas_sandbox_init(&sb);
    TEST_ASSERT(cupolas_sandbox_apply(&sb) == 0, "apply(disabled) is no-op", "failed");
    TEST_PASS("sandbox disabled / NULL is zero-overhead no-op");
}

#if defined(__linux__)

/* 子进程内应用沙箱并执行命令；返回子进程退出码（-1 = fork/wait 失败）。 */
static int run_in_sandbox(const cupolas_sandbox_t *sb, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (cupolas_sandbox_apply(sb) != 0)
            _exit(126); /* 沙箱应用失败（如内核不支持 Landlock） */
        execvp(argv[0], argv);
        _exit(127); /* exec 失败 */
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -2; /* signaled */
}

/* 子进程内：验证 rw_paths 可写 + 外部只读路径写被拒。
 * 退出码：0 = 断言全部成立；其他 = 失败类型。 */
static void probe_write(const char *rw_file, const char *outside_file)
{
    int fd = open(rw_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        _exit(21); /* rw_paths 内写入被拒 */
    close(fd);

    fd = open(outside_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        close(fd);
        unlink(outside_file);
        _exit(22); /* 外部路径本应被 Landlock 拒绝 */
    }
    _exit(0);
}

static void test_sandbox_write_restriction(void)
{
    char rw_dir[] = "/tmp/sandbox_rw_XXXXXX";
    if (mkdtemp(rw_dir) == NULL) {
        TEST_SKIP("sandbox write restriction", "mkdtemp failed");
        return;
    }
    char rw_file[256];
    char outside_file[] = "/tmp/sandbox_outside_denied.txt";
    snprintf(rw_file, sizeof(rw_file), "%s/probe.txt", rw_dir);

    const char *rw_paths[] = {rw_dir, NULL};
    cupolas_sandbox_t sb;
    cupolas_sandbox_init(&sb);
    sb.enabled = 1;
    sb.rw_paths = rw_paths;

    pid_t pid = fork();
    if (pid == 0) {
        if (cupolas_sandbox_apply(&sb) != 0)
            _exit(126); /* 内核不支持 Landlock：父进程将 SKIP */
        probe_write(rw_file, outside_file);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    unlink(rw_file);
    rmdir(rw_dir);
    unlink(outside_file);

    if (code == 126) {
        TEST_SKIP("sandbox write restriction", "Landlock unavailable (kernel < 5.13 or no header)");
        return;
    }
    TEST_ASSERT(code == 0, "rw_paths writable, outside read-only denied", "write probe failed");
    TEST_PASS("Landlock default read-only + rw_paths write");
}

static void test_sandbox_deny_network(void)
{
    cupolas_sandbox_t sb;
    cupolas_sandbox_init(&sb);
    sb.enabled = 1;
    sb.deny_network = 1;

    pid_t pid = fork();
    if (pid == 0) {
        if (cupolas_sandbox_apply(&sb) != 0)
            _exit(126);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            close(fd);
            _exit(31); /* 网络未被阻止 */
        }
        _exit(errno == EPERM ? 0 : 32); /* 0 = seccomp 返回 EPERM */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    if (code == 126) {
        TEST_SKIP("sandbox deny_network", "Landlock unavailable; network check skipped");
        return;
    }
    TEST_ASSERT(code == 0, "socket() denied with EPERM under deny_network", "network not blocked");
    TEST_PASS("seccomp denies network syscalls when deny_network=1");
}

static void test_sandbox_enabled_exec(void)
{
    char *const argv[] = {"/bin/echo", "sandbox-ok", NULL};
    const char *rw_paths[] = {"/tmp", NULL};
    cupolas_sandbox_t sb;
    cupolas_sandbox_init(&sb);
    sb.enabled = 1;
    sb.rw_paths = rw_paths;

    int code = run_in_sandbox(&sb, argv);
    if (code == 126) {
        TEST_SKIP("sandbox enabled exec", "Landlock unavailable (kernel < 5.13 or no header)");
        return;
    }
    TEST_ASSERT(code == 0, "echo succeeds inside sandbox", "sandbox exec failed");
    TEST_PASS("command executes inside Landlock default-read-only sandbox");
}

#else /* !__linux__ */

static void test_sandbox_write_restriction(void)
{
    TEST_SKIP("sandbox write restriction", "non-Linux: Landlock N/A");
}

static void test_sandbox_deny_network(void)
{
    TEST_SKIP("sandbox deny_network", "non-Linux: seccomp N/A");
}

static void test_sandbox_enabled_exec(void)
{
    TEST_SKIP("sandbox enabled exec", "non-Linux: native sandbox N/A");
}

#endif /* __linux__ */

int main(void)
{
    printf("========================================================\n");
    printf("  cupolas sandbox 单元测试（S-7: Landlock + seccomp）\n");
    printf("========================================================\n\n");

    RUN_TEST(test_sandbox_init);
    RUN_TEST(test_sandbox_noop);
    RUN_TEST(test_sandbox_enabled_exec);
    RUN_TEST(test_sandbox_write_restriction);
    RUN_TEST(test_sandbox_deny_network);

    printf("\n========================================================\n");
    printf("  结果: %d 通过, %d 失败, %d 跳过\n", g_tests_passed, g_tests_failed,
           g_tests_skipped);
    printf("========================================================\n");

    return g_tests_failed == 0 ? 0 : 1;
}
