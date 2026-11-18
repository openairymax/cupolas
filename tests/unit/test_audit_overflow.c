// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * test_audit_overflow.c - Audit Overflow Handler Unit Tests
 */

#include "audit_overflow.h"
#include "error.h"
#include "platform.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
/* 该 SDK 组合的 io.h 未定义 struct _finddata_t，枚举改用 Win32 原生面。 */
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

/* A-5：统计目录下以 prefix 开头的普通文件数；清理同前缀文件。 */
static int t_count_files(const char *dir, const char *prefix)
{
    int n = 0;
#if defined(_WIN32)
    char pat[512];
    snprintf(pat, sizeof(pat), "%s/%s*", dir, prefix);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            n++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    size_t plen = strlen(prefix);
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, plen) == 0) {
            char path[768];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
                n++;
        }
    }
    closedir(d);
#endif
    return n;
}

static void t_clean_files(const char *dir, const char *prefix)
{
#if defined(_WIN32)
    char pat[512];
    snprintf(pat, sizeof(pat), "%s/%s*", dir, prefix);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char path[768];
            snprintf(path, sizeof(path), "%s/%s", dir, fd.cFileName);
            remove(path);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *e;
    size_t plen = strlen(prefix);
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, plen) == 0) {
            char path[768];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            remove(path);
        }
    }
    closedir(d);
#endif
}

static void t_make_dir(const char *dir)
{
#if defined(_WIN32)
    (void)_mkdir(dir);
#else
    (void)mkdir(dir, 0755);
#endif
}

/* 首个匹配文件的大小；无匹配或首匹配为目录返回 -1。
 * windows 分支不得读 FindFirstFile 的 nFileSizeLow：文件仍被 handler 的
 * fopen(...,"a") 持有，目录索引中的大小要等关闭才刷新，读到 0 会误判空文件。
 * 改为按名字打开实测内容长度。 */
static long t_first_size(const char *dir, const char *prefix)
{
#if defined(_WIN32)
    char pat[512];
    snprintf(pat, sizeof(pat), "%s/%s*", dir, prefix);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    char name[512];
    snprintf(name, sizeof(name), "%s", fd.cFileName);
    int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    FindClose(h);
    if (is_dir)
        return -1;
    char path[768];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    long n = (fseek(f, 0, SEEK_END) == 0) ? (long)ftell(f) : -1;
    fclose(f);
    return n;
#else
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    struct dirent *e;
    size_t plen = strlen(prefix);
    long n = -1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, plen) != 0)
            continue;
        char path[768];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            n = (long)st.st_size;
            break;
        }
    }
    closedir(d);
    return n;
#endif
}

/* A-5-01：零溢出事件的 handler 生命周期内不得落盘任何文件。 */
static void test_overflow_lazy_no_file(void)
{
    printf("Test: overflow_lazy_no_file... ");

    const char *dir = AIRY_TMP_DIR "/cupolas_lazy_test";
    t_make_dir(dir);
    t_clean_files(dir, "audit_overflow_");

    overflow_handler_t *handler = overflow_handler_create(dir, 1, 10);
    assert(handler != NULL);

    overflow_handler_flush(handler);
    assert(t_count_files(dir, "audit_overflow_") == 0);

    overflow_handler_destroy(handler);
    assert(t_count_files(dir, "audit_overflow_") == 0);

    printf("PASS\n");
}

/* A-5-02：首个真实溢出事件才建文件，且内容非空。 */
static void test_overflow_first_event(void)
{
    printf("Test: overflow_first_event... ");

    const char *dir = AIRY_TMP_DIR "/cupolas_first_event";
    t_make_dir(dir);
    t_clean_files(dir, "audit_overflow_");

    overflow_handler_t *handler = overflow_handler_create(dir, 1, 10);
    assert(handler != NULL);

    audit_entry_t *entry = audit_entry_create(AUDIT_EVENT_PERMISSION, "lazy_agent",
                                              "lazy_action", "lazy_resource", "lazy_detail", 1);
    assert(entry != NULL);
    assert(overflow_handler_write(handler, entry) == 0);
    audit_entry_destroy(entry);
    overflow_handler_flush(handler);

    assert(t_count_files(dir, "audit_overflow_") == 1);
    assert(t_first_size(dir, "audit_overflow_") > 0);

    overflow_handler_destroy(handler);
    t_clean_files(dir, "audit_overflow_");

    printf("PASS\n");
}

/* A-5-03：越过 max_file_size 必须换新名字续写，不得重开旧文件清零计数。
 * 旧缺陷下 6000 条只会留下 1 个不断增长的文件。 */
static void test_overflow_rotate_unique(void)
{
    printf("Test: overflow_rotate_unique... ");

    const char *dir = AIRY_TMP_DIR "/cupolas_rotate_test";
    t_make_dir(dir);
    t_clean_files(dir, "audit_overflow_");

    overflow_handler_t *handler = overflow_handler_create(dir, 1, 10);
    assert(handler != NULL);

    for (int i = 0; i < 12000; i++) {
        char action[32];
        snprintf(action, sizeof(action), "act_%d", i);
        audit_entry_t *entry = audit_entry_create(AUDIT_EVENT_SANITIZER, "rot_agent", action,
                                                  "rot_resource", "rot_detail", 1);
        assert(entry != NULL);
        assert(overflow_handler_write(handler, entry) == 0);
        audit_entry_destroy(entry);
    }
    overflow_handler_flush(handler);

    int files = t_count_files(dir, "audit_overflow_");
    assert(files >= 2);

    overflow_handler_destroy(handler);
    t_clean_files(dir, "audit_overflow_");

    printf("PASS (%d files)\n", files);
}


static void test_overflow_handler_create_destroy(void)
{
    printf("Test: overflow_handler_create_destroy... ");

    overflow_handler_t *handler = overflow_handler_create(AIRY_TMP_DIR "/cupolas_test", 1, 100);
    assert(handler != NULL);

    overflow_handler_destroy(handler);
    printf("PASS\n");
}

static void test_overflow_dir_already_exists(void)
{
    printf("Test: overflow_dir_already_exists... ");

    /* EEXIST 回归：目录预创建后 create，溢出目录必须保持原值，
     * 不得误判失败而回退 AIRY_TMP_DIR"/cupolas_audit"。 */
    const char *dir = AIRY_TMP_DIR "/cupolas_eexist_test";
#if defined(_WIN32)
    (void)_mkdir(dir);
#else
    (void)mkdir(dir, 0755);
#endif

    overflow_handler_t *handler = overflow_handler_create(dir, 1, 100);
    assert(handler != NULL);
    assert(strcmp(overflow_get_dir(handler), dir) == 0);

    overflow_handler_destroy(handler);
    printf("PASS\n");
}

static void test_overflow_level_check(void)
{
    printf("Test: overflow_level_check... ");

    assert(overflow_handler_check_level(0, 100) == OVERFLOW_LEVEL_NORMAL);
    assert(overflow_handler_check_level(79, 100) == OVERFLOW_LEVEL_NORMAL);

    assert(overflow_handler_check_level(80, 100) == OVERFLOW_LEVEL_WARNING);
    assert(overflow_handler_check_level(94, 100) == OVERFLOW_LEVEL_WARNING);

    assert(overflow_handler_check_level(95, 100) == OVERFLOW_LEVEL_CRITICAL);
    assert(overflow_handler_check_level(99, 100) == OVERFLOW_LEVEL_CRITICAL);

    assert(overflow_handler_check_level(100, 100) == OVERFLOW_LEVEL_SPILLING);
    assert(overflow_handler_check_level(150, 100) == OVERFLOW_LEVEL_SPILLING);

    assert(overflow_handler_check_level(0, 0) == OVERFLOW_LEVEL_SPILLING);

    printf("PASS\n");
}

static void test_overflow_write_and_stats(void)
{
    printf("Test: overflow_write_and_stats... ");

    overflow_handler_t *handler = overflow_handler_create(AIRY_TMP_DIR "/cupolas_test", 10, 0);
    assert(handler != NULL);

    audit_entry_t *entry = audit_entry_create(AUDIT_EVENT_PERMISSION, "test_agent", "test_action",
                                              "test_resource", "test_detail", 1);
    assert(entry != NULL);

    int result = overflow_handler_write(handler, entry);
    assert(result == 0);

    audit_entry_destroy(entry);

    overflow_stats_t stats;
    overflow_handler_get_stats(handler, &stats);
    assert(stats.total_events_received >= 1);
    assert(stats.events_written_to_disk >= 1);
    assert(stats.disk_write_errors == 0);

    overflow_handler_flush(handler);

    overflow_handler_reset_stats(handler);
    overflow_handler_get_stats(handler, &stats);
    assert(stats.total_events_received == 0);

    overflow_handler_destroy(handler);
    printf("PASS\n");
}

static void test_overflow_null_handling(void)
{
    printf("Test: overflow_null_handling... ");

    /* overflow_handler_create 的返回值不得包裹在 assert() 中：
     * Debug 模式下 handler 被创建（含内存+文件句柄+flush 线程）但指针被丢弃，
     * 导致内存+文件+线程泄漏；NDEBUG 模式下 assert 展开为 ((void)0) 不求值，
     * handler 根本不会被创建。故拆出 create，确保两种模式下都正确创建+销毁。
     * overflow_handler_create(NULL, 0, 0) 使用默认值创建，应返回非 NULL。 */
    overflow_handler_t *null_handler = overflow_handler_create(NULL, 0, 0);
    assert(null_handler != NULL);
    if (null_handler) {
        overflow_handler_destroy(null_handler);
    }

    audit_entry_t *entry = audit_entry_create(AUDIT_EVENT_SYSTEM, NULL, NULL, NULL, NULL, 0);
    if (entry) {
        int result = overflow_handler_write(NULL, entry);
        assert(result == AIRY_ERR_NULL_POINTER);
        audit_entry_destroy(entry);
    }

    overflow_handler_flush(NULL);

    overflow_stats_t stats;
    overflow_handler_get_stats(NULL, &stats);
    assert(stats.total_events_received == 0);

    overflow_handler_reset_stats(NULL);

    overflow_handler_destroy(NULL);

    printf("PASS\n");
}

static void test_queue_ex_create_destroy(void)
{
    printf("Test: queue_ex_create_destroy... ");

    audit_queue_ex_t *queue = audit_queue_ex_create(100, AIRY_TMP_DIR "/cupolas_test", 5);
    assert(queue != NULL);

    assert(audit_queue_ex_size(queue) == 0);

    audit_queue_ex_destroy(queue);
    printf("PASS\n");
}

static void test_queue_ex_push_pop(void)
{
    printf("Test: queue_ex_push_pop... ");

    audit_queue_ex_t *queue = audit_queue_ex_create(10, AIRY_TMP_DIR "/cupolas_test", 5);
    assert(queue != NULL);

    audit_entry_t *entry =
        audit_entry_create(AUDIT_EVENT_PERMISSION, "agent1", "action1", "resource1", "detail1", 1);
    assert(entry != NULL);

    int result = audit_queue_ex_push(queue, entry);
    assert(result == 0);

    assert(audit_queue_ex_size(queue) == 1);

    audit_entry_t *popped;
    result = audit_queue_ex_pop(queue, &popped);
    assert(result == 0);
    assert(popped != NULL);
    assert(strcmp(popped->agent_id, "agent1") == 0);

    audit_entry_destroy(popped);

    assert(audit_queue_ex_size(queue) == 0);

    audit_queue_ex_destroy(queue);
    printf("PASS\n");
}

static int g_overflow_callback_invoked = 0;

static void test_overflow_callback(overflow_level_t level, size_t queue_size, size_t max_size,
                                   void *user_data)
{
    (void)queue_size;
    (void)max_size;
    (void)user_data;
    g_overflow_callback_invoked++;
    assert(level >= OVERFLOW_LEVEL_WARNING);
}

static void test_queue_ex_overflow_callback_called(void)
{
    printf("Test: queue_ex_overflow_callback... ");

    audit_queue_ex_t *queue = audit_queue_ex_create(3, AIRY_TMP_DIR "/cupolas_test", 5);
    assert(queue != NULL);

    g_overflow_callback_invoked = 0;
    int cb_result = audit_queue_ex_set_overflow_callback(queue, test_overflow_callback, NULL);
    assert(cb_result == 0);

    for (int i = 0; i < 4; i++) {
        char agent[32], action[32];
        snprintf(agent, sizeof(agent), "agent%d", i);
        snprintf(action, sizeof(action), "action%d", i);

        audit_entry_t *entry =
            audit_entry_create(AUDIT_EVENT_PERMISSION, agent, action, "resource", "detail", 1);

        if (entry) {
            audit_queue_ex_push_with_callback(queue, entry, test_overflow_callback, NULL);
        }
    }

    assert(g_overflow_callback_invoked > 0 ||
           audit_queue_ex_get_overflow_level(queue) >= OVERFLOW_LEVEL_WARNING);

    audit_queue_ex_destroy(queue);
    printf("PASS\n");
}

static void test_queue_ex_stats(void)
{
    printf("Test: queue_ex_stats... ");

    audit_queue_ex_t *queue = audit_queue_ex_create(10, AIRY_TMP_DIR "/cupolas_test", 5);
    assert(queue != NULL);

    uint64_t pushed, popped, spilled, dropped;
    audit_queue_ex_get_stats(queue, &pushed, &popped, &spilled, &dropped);
    assert(pushed == 0);
    assert(popped == 0);
    assert(spilled == 0);
    assert(dropped == 0);

    for (int i = 0; i < 5; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "entry_%d", i);

        audit_entry_t *entry =
            audit_entry_create(AUDIT_EVENT_SANITIZER, buf, "action", "resource", "detail", 1);

        if (entry) {
            audit_queue_ex_push(queue, entry);
        }
    }

    audit_queue_ex_get_stats(queue, &pushed, &popped, &spilled, &dropped);
    assert(pushed >= 5);

    audit_queue_ex_shutdown(queue, false);
    audit_queue_ex_destroy(queue);
    printf("PASS\n");
}

int main(void)
{
    printf("=== Audit Overflow Tests ===\n");

    test_overflow_handler_create_destroy();
    test_overflow_dir_already_exists();
    test_overflow_lazy_no_file();
    test_overflow_first_event();
    test_overflow_rotate_unique();
    test_overflow_level_check();
    test_overflow_write_and_stats();
    test_overflow_null_handling();
    test_queue_ex_create_destroy();
    test_queue_ex_push_pop();
    test_queue_ex_overflow_callback_called();
    test_queue_ex_stats();

    printf("=== All tests PASSED ===\n");
    return 0;
}
