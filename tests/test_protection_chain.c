/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * test_protection_chain.c - cupolas protection chain integration test (INT-11)
 *
 * Covers the protection chain end to end:
 *   INT-11.1  default-level sanitization of XSS/SQL/shell attack vectors
 *   INT-11.2  level-driven enforcement (NONE/LOW/MEDIUM/HIGH/MAX)
 *   INT-11.3  RBAC permission engine with role isolation
 *
 * The sanitizer is escape- or reject-based; it never removes keywords. The
 * assertions therefore verify the documented result code and the absence of
 * unescaped metacharacters, not the absence of words like "onerror".
 */

#include "cupolas.h"
#include "sanitizer/sanitizer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Test Macros
 * ============================================================================ */

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name)                      \
    do {                                    \
        printf("  Running " #name "...\n"); \
        test_##name();                      \
        printf("  PASSED\n");               \
        g_tests_passed++;                   \
    } while (0)

static int g_tests_passed = 0;
static int g_tests_failed = 0;

/* ============================================================================
 * Helpers
 * ============================================================================ */

static int str_contains(const char *haystack, const char *needle)
{
    if (!haystack || !needle)
        return 0;
    return strstr(haystack, needle) != NULL;
}

static int has_raw_angle(const char *text)
{
    return text && (strchr(text, '<') != NULL || strchr(text, '>') != NULL);
}

static void ctx_set_level(sanitize_context_t *ctx, sanitize_level_t level)
{
    sanitizer_default_context(ctx);
    ctx->level = level;
}

/* ============================================================================
 * INT-11.1: Default-level sanitization (escape contract, MEDIUM by default)
 * ============================================================================ */

TEST(sanitize_xss_default_level)
{
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);
    assert(init_err == AIRY_OK);

    const char *xss = "<script>alert('xss')</script>";
    char output[256];
    memset(output, 0, sizeof(output));

    int ret = cupolas_sanitize_input(xss, output, sizeof(output));
    assert(ret == 0);

    /* Every angle bracket must be escaped, so no raw tag survives. */
    assert(!has_raw_angle(output));
    assert(strcmp(output, xss) != 0);
    printf("    XSS escaped: '%s' -> '%s'\n", xss, output);

    cupolas_cleanup();
}

TEST(sanitize_sql_default_level)
{
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    const char *sql = "' OR '1'='1";
    char output[256];
    memset(output, 0, sizeof(output));

    int ret = cupolas_sanitize_input(sql, output, sizeof(output));
    assert(ret == 0);

    /* SQL escaping doubles the leading quote. */
    assert(output[0] == '\'' && output[1] == '\'');
    assert(strcmp(output, sql) != 0);
    printf("    SQL escaped: '%s' -> '%s'\n", sql, output);

    cupolas_cleanup();
}

TEST(sanitize_attack_vectors)
{
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* XSS vectors: all angle brackets must be neutralized. */
    const char *xss[] = {
        "<img src=x onerror=alert(1)>",
        "javascript:void(0)",
        "<body onload=alert('xss')>",
        "\"><script>alert(1)</script>",
    };

    for (size_t i = 0; i < sizeof(xss) / sizeof(xss[0]); i++) {
        char output[256];
        memset(output, 0, sizeof(output));

        int ret = cupolas_sanitize_input(xss[i], output, sizeof(output));
        assert(ret == 0);
        assert(!has_raw_angle(output));
        printf("    XSS vector %zu neutralized: '%s' -> '%s'\n", i + 1, xss[i], output);
    }

    /* Shell vectors: metacharacters must be escaped, not passed through. */
    const char *shell[] = {
        "foo; rm -rf /",
        "cat /etc/passwd | mail attacker",
        "$(whoami) `id`",
    };

    for (size_t i = 0; i < sizeof(shell) / sizeof(shell[0]); i++) {
        char output[256];
        memset(output, 0, sizeof(output));

        int ret = cupolas_sanitize_input(shell[i], output, sizeof(output));
        assert(ret == 0);
        assert(strcmp(output, shell[i]) != 0);
        printf("    Shell vector %zu escaped: '%s' -> '%s'\n", i + 1, shell[i], output);
    }

    cupolas_cleanup();
}

TEST(sanitize_safe_passthrough)
{
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    const char *safe_input = "Hello, World! This is safe text.";
    char output[256];
    memset(output, 0, sizeof(output));

    int ret = cupolas_sanitize_input(safe_input, output, sizeof(output));
    assert(ret == 0);

    /* Benign input is preserved byte for byte. */
    assert(strcmp(output, safe_input) == 0);
    printf("    Safe input preserved: '%s'\n", output);

    cupolas_cleanup();
}

TEST(sanitize_null_and_bounds)
{
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    char output[256];

    /* NULL and zero-size arguments are rejected up front. */
    assert(cupolas_sanitize_input(NULL, output, sizeof(output)) != 0);
    assert(cupolas_sanitize_input("data", NULL, 0) != 0);

    /* A small buffer must stay inside its declared size (canary intact). */
    char small[8];
    memset(small, 0xAA, sizeof(small));

    int ret = cupolas_sanitize_input("<script>alert(1)</script>", small, 4);
    assert(ret == 0 || ret < 0);
    assert(strlen(small) < 4);
    for (size_t i = 4; i < sizeof(small); i++) {
        assert((unsigned char)small[i] == 0xAA);
    }
    printf("    NULL/zero-size rejected, small buffer bounded to '%s'\n", small);

    cupolas_cleanup();
}

/* ============================================================================
 * INT-11.2: Level-driven enforcement (NONE/LOW/MEDIUM/HIGH/MAX)
 * ============================================================================ */

TEST(level_none_passthrough)
{
    sanitizer_t *san = sanitizer_create(NULL);
    assert(san != NULL);

    sanitize_context_t ctx;
    ctx_set_level(&ctx, SANITIZE_LEVEL_NONE);

    const char *input = "<script>alert(1)</script>";
    char output[256];

    assert(sanitizer_sanitize(san, input, output, sizeof(output), &ctx) == SANITIZE_OK);
    assert(strcmp(output, input) == 0);
    assert(sanitizer_is_safe(san, input, &ctx));
    printf("    NONE passes input through unchanged\n");

    sanitizer_destroy(san);
}

TEST(level_low_medium_escape)
{
    sanitizer_t *san = sanitizer_create(NULL);
    assert(san != NULL);

    const char *input = "<script>alert(1)</script>";
    char output[256];

    sanitize_context_t ctx;
    ctx_set_level(&ctx, SANITIZE_LEVEL_LOW);
    assert(sanitizer_sanitize(san, input, output, sizeof(output), &ctx) == SANITIZE_MODIFIED);
    assert(!has_raw_angle(output));
    assert(!sanitizer_is_safe(san, input, &ctx));

    ctx_set_level(&ctx, SANITIZE_LEVEL_MEDIUM);
    assert(sanitizer_sanitize(san, input, output, sizeof(output), &ctx) == SANITIZE_MODIFIED);
    assert(!has_raw_angle(output));
    assert(sanitizer_is_safe(san, "plain text 42", &ctx));
    printf("    LOW/MEDIUM escape metacharacters: '%s' -> '%s'\n", input, output);

    sanitizer_destroy(san);
}

TEST(level_high_whitelist)
{
    sanitizer_t *san = sanitizer_create(NULL);
    assert(san != NULL);

    sanitize_context_t ctx;
    ctx_set_level(&ctx, SANITIZE_LEVEL_HIGH);

    char output[256];

    /* Non-whitelisted input is rejected and the output stays empty. */
    char dirty[64];
    memset(dirty, 0x5A, sizeof(dirty));
    assert(sanitizer_sanitize(san, "<script>", dirty, sizeof(dirty), &ctx) == SANITIZE_REJECTED);
    assert(dirty[0] == '\0');
    assert(!sanitizer_is_safe(san, "<script>", &ctx));

    /* Whitelisted input passes through untouched. */
    const char *clean = "Hello, world-42";
    assert(sanitizer_sanitize(san, clean, output, sizeof(output), &ctx) == SANITIZE_OK);
    assert(strcmp(output, clean) == 0);
    assert(sanitizer_is_safe(san, clean, &ctx));
    printf("    HIGH rejects non-whitelisted and accepts plain text\n");

    sanitizer_destroy(san);
}

TEST(level_max_rejects_all)
{
    sanitizer_t *san = sanitizer_create(NULL);
    assert(san != NULL);

    sanitize_context_t ctx;
    ctx_set_level(&ctx, SANITIZE_LEVEL_MAX);

    char output[256];
    memset(output, 0x5A, sizeof(output));
    assert(sanitizer_sanitize(san, "anything", output, sizeof(output), &ctx) == SANITIZE_REJECTED);
    assert(output[0] == '\0');
    assert(!sanitizer_is_safe(san, "anything", &ctx));
    printf("    MAX rejects all input\n");

    sanitizer_destroy(san);
}

TEST(level_medium_rule_stage)
{
    sanitizer_t *san = sanitizer_create(NULL);
    assert(san != NULL);

    sanitize_context_t ctx;
    ctx_set_level(&ctx, SANITIZE_LEVEL_MEDIUM);

    char output[256];

    /* Literal rule with a replacement rewrites the escaped output. */
    assert(sanitizer_add_rule(san, "DROP TABLE", "[removed]") == 0);
    assert(sanitizer_sanitize(san, "1; DROP TABLE users", output, sizeof(output), &ctx) ==
           SANITIZE_MODIFIED);
    assert(!str_contains(output, "DROP TABLE"));
    assert(str_contains(output, "[removed]"));

    /* Rule without a replacement fails closed. */
    assert(sanitizer_add_rule(san, "FORBIDDEN", NULL) == 0);
    assert(sanitizer_sanitize(san, "FORBIDDEN", output, sizeof(output), &ctx) == SANITIZE_REJECTED);
    printf("    MEDIUM applies literal rules and fails closed on reject rules\n");

    sanitizer_destroy(san);
}

/* ============================================================================
 * INT-11.3: RBAC permission engine with role isolation
 * ============================================================================ */

TEST(permission_engine_admin_access)
{
    /* Add admin permission rule and verify admin has access */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add an admin permission rule: allow all actions on all resources */
    rc = cupolas_add_permission_rule("admin", "*", "*", 1, 100);
    assert(rc == 0);

    /* Admin should have read permission */
    int result = cupolas_check_permission("admin", "read", "/data/file.txt", NULL);
    assert(result == 1);

    /* Admin should have write permission */
    result = cupolas_check_permission("admin", "write", "/data/file.txt", NULL);
    assert(result == 1);

    /* Admin should have execute permission */
    result = cupolas_check_permission("admin", "execute", "/bin/tool", NULL);
    assert(result == 1);

    printf("    Admin has full access to all resources\n");

    cupolas_cleanup();
}

TEST(permission_engine_user_denied)
{
    /* Check that a user without permission is denied */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add a specific permission for user "alice" to read only */
    rc = cupolas_add_permission_rule("alice", "read", "/data/public/*", 1, 50);
    assert(rc == 0);

    /* Alice should have read permission on public data */
    int result = cupolas_check_permission("alice", "read", "/data/public/doc.txt", NULL);
    assert(result == 1);

    /* Alice should NOT have write permission */
    result = cupolas_check_permission("alice", "write", "/data/public/doc.txt", NULL);
    assert(result == 0);

    /* Alice should NOT have access to private data */
    result = cupolas_check_permission("alice", "read", "/data/private/secret.txt", NULL);
    assert(result == 0);

    printf("    User 'alice' has read-only access to public data\n");

    cupolas_cleanup();
}

TEST(permission_engine_guest_isolation)
{
    /* Check guest role isolation */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add admin rule with high priority */
    rc = cupolas_add_permission_rule("admin", "*", "*", 1, 100);
    assert(rc == 0);

    /* Add guest rule with low priority - only read public */
    rc = cupolas_add_permission_rule("guest", "read", "/public/*", 1, 10);
    assert(rc == 0);

    /* Explicitly deny guest access to admin area */
    rc = cupolas_add_permission_rule("guest", "*", "/admin/*", 0, 90);
    assert(rc == 0);

    /* Guest should access public resources */
    int result = cupolas_check_permission("guest", "read", "/public/index.html", NULL);
    assert(result == 1);

    /* Guest should NOT access admin area (deny rule has higher priority) */
    result = cupolas_check_permission("guest", "read", "/admin/dashboard", NULL);
    assert(result == 0);

    /* Guest should NOT write to public area */
    result = cupolas_check_permission("guest", "write", "/public/index.html", NULL);
    assert(result == 0);

    /* Admin should still access admin area */
    result = cupolas_check_permission("admin", "read", "/admin/dashboard", NULL);
    assert(result == 1);

    printf("    Guest role isolated from admin area\n");

    cupolas_cleanup();
}

TEST(permission_engine_undefined_defaults_to_deny)
{
    /* Check undefined permission defaults to deny */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* No rules added - everything should be denied by default */
    /* Unknown user should be denied */
    int result = cupolas_check_permission("unknown_user", "read", "/any/file.txt", NULL);
    assert(result == 0);

    /* Unknown action should be denied */
    result = cupolas_check_permission("admin", "unknown_action", "/any/file.txt", NULL);
    assert(result == 0);

    /* Unknown resource should be denied */
    result = cupolas_check_permission("admin", "read", "/nonexistent/path", NULL);
    assert(result == 0);

    printf("    Undefined permissions default to deny\n");

    cupolas_cleanup();
}

TEST(permission_engine_priority_ordering)
{
    /* Check priority-based rule ordering */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add a broad deny rule with medium priority */
    rc = cupolas_add_permission_rule("*", "*", "/restricted/*", 0, 50);
    assert(rc == 0);

    /* Add a specific allow rule with higher priority */
    rc = cupolas_add_permission_rule("bob", "read", "/restricted/bob_files/*", 1, 75);
    assert(rc == 0);

    /* Bob should be allowed to read his own files */
    int result = cupolas_check_permission("bob", "read", "/restricted/bob_files/doc.txt", NULL);
    assert(result == 1);

    /* Bob should NOT write to his files */
    result = cupolas_check_permission("bob", "write", "/restricted/bob_files/doc.txt", NULL);
    assert(result == 0);

    /* Other user should be denied access to restricted area */
    result = cupolas_check_permission("carol", "read", "/restricted/bob_files/doc.txt", NULL);
    assert(result == 0);

    printf("    Priority-based rule ordering works correctly\n");

    cupolas_cleanup();
}

TEST(permission_engine_cache_clear)
{
    /* Clear permission cache and verify rules still work */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add a permission rule */
    rc = cupolas_add_permission_rule("eve", "read", "/cache_test/*", 1, 50);
    assert(rc == 0);

    /* First check - should be allowed */
    int result = cupolas_check_permission("eve", "read", "/cache_test/file.txt", NULL);
    assert(result == 1);

    /* Clear the permission cache */
    cupolas_clear_permission_cache();

    /* After cache clear, permission should still be enforced */
    result = cupolas_check_permission("eve", "read", "/cache_test/file.txt", NULL);
    assert(result == 1);

    /* After cache clear, non-permitted access should still be denied */
    result = cupolas_check_permission("eve", "write", "/cache_test/file.txt", NULL);
    assert(result == 0);

    printf("    Permission cache cleared and re-verified\n");

    cupolas_cleanup();
}

TEST(permission_engine_wildcards)
{
    /* Test wildcard matching */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add a wildcard rule for all agents on a specific resource */
    rc = cupolas_add_permission_rule("*", "read", "/public/*", 1, 25);
    assert(rc == 0);

    /* Multiple agents should have access */
    int result = cupolas_check_permission("user_a", "read", "/public/index.html", NULL);
    assert(result == 1);

    result = cupolas_check_permission("user_b", "read", "/public/about.html", NULL);
    assert(result == 1);

    result = cupolas_check_permission("user_c", "read", "/public/contact.html", NULL);
    assert(result == 1);

    /* But none should have write access */
    result = cupolas_check_permission("user_a", "write", "/public/index.html", NULL);
    assert(result == 0);

    printf("    Wildcard matching works for all agents\n");

    cupolas_cleanup();
}

TEST(permission_engine_context)
{
    /* Test permission check with context */
    airy_err_t init_err = AIRY_OK;
    int rc = cupolas_init(NULL, &init_err);
    assert(rc == 0);

    /* Add a rule for a specific agent */
    rc = cupolas_add_permission_rule("context_user", "read", "/context/*", 1, 50);
    assert(rc == 0);

    /* Check with NULL context (should work) */
    int result = cupolas_check_permission("context_user", "read", "/context/file.txt", NULL);
    assert(result == 1);

    /* Check with a context string (should still work) */
    result =
        cupolas_check_permission("context_user", "read", "/context/file.txt", "session=abc123");
    assert(result == 1);

    printf("    Permission check with context works\n");

    cupolas_cleanup();
}

/* ============================================================================
 * Main: Run all tests
 * ============================================================================ */

int main(void)
{
    printf("=== cupolas Protection Chain Integration Tests (INT-11) ===\n\n");

    printf("--- INT-11.1: Default-level sanitization ---\n");
    RUN_TEST(sanitize_xss_default_level);
    RUN_TEST(sanitize_sql_default_level);
    RUN_TEST(sanitize_attack_vectors);
    RUN_TEST(sanitize_safe_passthrough);
    RUN_TEST(sanitize_null_and_bounds);

    printf("\n--- INT-11.2: Level-driven enforcement ---\n");
    RUN_TEST(level_none_passthrough);
    RUN_TEST(level_low_medium_escape);
    RUN_TEST(level_high_whitelist);
    RUN_TEST(level_max_rejects_all);
    RUN_TEST(level_medium_rule_stage);

    printf("\n--- INT-11.3: RBAC permission engine ---\n");
    RUN_TEST(permission_engine_admin_access);
    RUN_TEST(permission_engine_user_denied);
    RUN_TEST(permission_engine_guest_isolation);
    RUN_TEST(permission_engine_undefined_defaults_to_deny);
    RUN_TEST(permission_engine_priority_ordering);
    RUN_TEST(permission_engine_cache_clear);
    RUN_TEST(permission_engine_wildcards);
    RUN_TEST(permission_engine_context);

    printf("\n=== Results: %d passed, %d failed ===\n", g_tests_passed, g_tests_failed);

    return g_tests_failed > 0 ? 1 : 0;
}
