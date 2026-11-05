// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 */

#include "yaml_minimal.h" /* SP03: migrated to commons/utils/config_unified/ */
#include "airy_memory.h"  /* AIRY_FREE：yaml_serialize 返回 AIRY 分配器内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)               \
    do {                         \
        tests_run++;             \
        printf("  %-50s", name); \
    } while (0)
#define PASS()              \
    do {                    \
        tests_passed++;     \
        printf("[PASS]\n"); \
    } while (0)
#define FAIL(msg)                   \
    do {                            \
        printf("[FAIL] %s\n", msg); \
    } while (0)
#define ASSERT(cond, msg) \
    do {                  \
        if (!(cond)) {    \
            FAIL(msg);    \
            return;       \
        }                 \
    } while (0)

static void test_create_destroy(void)
{
    TEST("Create and destroy");
    yaml_document_t *doc = yaml_create();
    ASSERT(doc != NULL, "yaml_create returned NULL");
    ASSERT(doc->root == NULL, "root should be NULL");
    yaml_destroy(doc);
    PASS();
}

static void test_parse_empty(void)
{
    TEST("Parse empty input");
    yaml_document_t *doc = yaml_create();
    int rc = yaml_parse_string(doc, "", 0);
    ASSERT(rc == 0, "empty input accepted as empty scalar");
    ASSERT(doc->root != NULL, "root should not be NULL");
    yaml_destroy(doc);
    PASS();
}

static void test_parse_scalar(void)
{
    TEST("Parse simple scalar");
    yaml_document_t *doc = yaml_create();
    int rc = yaml_parse_string(doc, "hello world", 11);
    ASSERT(rc == 0, "scalar parse should succeed");
    ASSERT(doc->root != NULL, "root should not be NULL");
    ASSERT(doc->root->type == YAML_NODE_SCALAR, "should be scalar");
    const char *val = yaml_as_string(doc->root, NULL);
    ASSERT(val != NULL, "scalar value should not be NULL");
    yaml_destroy(doc);
    PASS();
}

static void test_parse_sequence(void)
{
    TEST("Parse simple sequence");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "- apple\n- banana\n- cherry\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "sequence parse should succeed");
    ASSERT(doc->root != NULL, "root should not be NULL");
    ASSERT(doc->root->type == YAML_NODE_SEQUENCE, "should be sequence");
    ASSERT(yaml_size(doc->root) == 3, "sequence should have 3 items");

    struct yaml_node *item0 = yaml_get_index(doc->root, 0);
    ASSERT(item0 != NULL, "item 0 should exist");
    struct yaml_node *item1 = yaml_get_index(doc->root, 1);
    ASSERT(item1 != NULL, "item 1 should exist");

    yaml_destroy(doc);
    PASS();
}

static void test_null_lookup(void)
{
    TEST("Null key lookup returns default");
    ASSERT(yaml_as_string(NULL, "default") != NULL, "null node returns default");
    ASSERT(yaml_as_int64(NULL, 999) == 999, "null int64 default");
    ASSERT(yaml_as_double(NULL, 99.9) == 99.9, "null double default");
    ASSERT(yaml_as_bool(NULL, true) == true, "null bool default");
    ASSERT(yaml_has_key(NULL, "x") == false, "has_key on null");
    PASS();
}

static void test_null_document_parse(void)
{
    TEST("Null document param rejected");
    int rc = yaml_parse_string(NULL, "x", 1);
    ASSERT(rc != 0, "null doc should be rejected");
    PASS();
}

static void test_null_input_parse(void)
{
    TEST("Null input param rejected");
    yaml_document_t *doc = yaml_create();
    int rc = yaml_parse_string(doc, NULL, 5);
    ASSERT(rc != 0, "null input should be rejected");
    yaml_destroy(doc);
    PASS();
}

static void test_destroy_null(void)
{
    TEST("Destroy null document");
    yaml_destroy(NULL);
    PASS();
}

static void test_key_with_null_value(void)
{
    TEST("Key with null value");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "key: ~\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "null value parse should succeed");
    ASSERT(yaml_has_key(doc->root, "key") == true, "has_key for null-valued key");
    struct yaml_node *key_node = yaml_get(doc->root, "key");
    ASSERT(key_node != NULL, "key should exist");
    yaml_destroy(doc);
    PASS();
}

static void test_dump_scalar(void)
{
    TEST("Dump scalar node");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "hello";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse scalar");

    char buf[4096] = {0};
    yaml_dump(doc->root, buf, sizeof(buf), 0);
    ASSERT(strlen(buf) > 0, "dump should produce output");

    char *serialized = yaml_serialize(doc);
    ASSERT(serialized != NULL, "serialize should produce output");
    AIRY_FREE(serialized);

    yaml_destroy(doc);
    PASS();
}

static void test_dump_sequence(void)
{
    TEST("Dump sequence node");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "- a\n- b\n- c\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse sequence");

    char buf[4096] = {0};
    yaml_dump(doc->root, buf, sizeof(buf), 0);
    ASSERT(strlen(buf) > 0, "dump should produce output");

    char *serialized = yaml_serialize(doc);
    ASSERT(serialized != NULL, "serialize should produce output");
    AIRY_FREE(serialized);

    yaml_destroy(doc);
    PASS();
}

static void test_multi_document(void)
{
    TEST("Multi-document YAML");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "---\ndoc1: first\n...\n---\ndoc2: second\n";
    int rc = yaml_parse_multi(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "multi-doc parse");
    ASSERT(doc->next != NULL, "should have second document");
    struct yaml_node *root2 = yaml_root(doc->next);
    ASSERT(root2 != NULL, "second doc root should exist");
    yaml_destroy_chain(doc);
    PASS();
}

static void test_sequence_out_of_bounds(void)
{
    TEST("Sequence out of bounds access");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "- a\n- b\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "sequence parse");
    ASSERT(yaml_size(doc->root) == 2, "size is 2");
    ASSERT(yaml_get_index(doc->root, 5) == NULL, "out of bounds returns NULL");
    yaml_destroy(doc);
    PASS();
}

static void test_double_parse(void)
{
    TEST("Parse key: double value");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "ratio: 3.14\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse should succeed");
    struct yaml_node *ratio = yaml_get(doc->root, "ratio");
    ASSERT(ratio != NULL, "ratio should exist");
    ASSERT(yaml_as_double(ratio, -1.0) == 3.14, "ratio should be 3.14");
    yaml_destroy(doc);
    PASS();
}

static void test_int_parse(void)
{
    TEST("Parse key: int value");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "count: 42\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse should succeed");
    struct yaml_node *cnt = yaml_get(doc->root, "count");
    ASSERT(cnt != NULL, "count should exist");
    ASSERT(yaml_as_int64(cnt, -1) == 42, "count should be 42");
    yaml_destroy(doc);
    PASS();
}

static void test_bool_parse(void)
{
    TEST("Parse key: bool values");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "val: true\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse should succeed");
    struct yaml_node *val = yaml_get(doc->root, "val");
    ASSERT(val != NULL, "val should exist");
    ASSERT(yaml_as_bool(val, false) == true, "val should be true");
    yaml_destroy(doc);
    PASS();
}

static void test_string_parse(void)
{
    TEST("Parse key: string value");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "name: AgentRT\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse should succeed");
    struct yaml_node *name = yaml_get(doc->root, "name");
    ASSERT(name != NULL, "name should exist");
    ASSERT(strcmp(yaml_as_string(name, ""), "AgentRT") == 0, "name should be AgentRT");
    yaml_destroy(doc);
    PASS();
}

static void test_plain_scalar_with_colon(void)
{
    TEST("Parse plain scalar containing ':'");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "base_url: https://api.example.com\n"
                       "endpoint: http://localhost:11434/v1\n"
                       "tag: foo:bar\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "plain scalar with ':' should parse");
    ASSERT(strcmp(yaml_as_string(yaml_get(doc->root, "base_url"), ""),
                  "https://api.example.com") == 0,
           "scheme ':' must stay inside the scalar");
    ASSERT(strcmp(yaml_as_string(yaml_get(doc->root, "endpoint"), ""),
                  "http://localhost:11434/v1") == 0,
           "port ':' must stay inside the scalar");
    ASSERT(strcmp(yaml_as_string(yaml_get(doc->root, "tag"), ""), "foo:bar") == 0,
           "':' without following space is not a key separator");
    yaml_destroy(doc);
    PASS();
}

static void test_quoted_double(void)
{
    TEST("Parse double-quoted string");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "key: \"quoted value\"\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse should succeed");
    struct yaml_node *k = yaml_get(doc->root, "key");
    ASSERT(k != NULL, "key should exist");
    ASSERT(strcmp(yaml_as_string(k, ""), "quoted value") == 0, "quoted value");
    yaml_destroy(doc);
    PASS();
}

static void test_has_key_null_node(void)
{
    TEST("has_key on non-mapping returns false");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "just_a_string\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse scalar");
    ASSERT(yaml_has_key(doc->root, "anything") == false, "has_key on scalar returns false");
    yaml_destroy(doc);
    PASS();
}

static void test_sequence_get_index_negative(void)
{
    TEST("Sequence get_index with -1");
    yaml_document_t *doc = yaml_create();
    const char *yaml = "- a\n- b\n";
    int rc = yaml_parse_string(doc, yaml, strlen(yaml));
    ASSERT(rc == 0, "parse sequence");
    ASSERT(yaml_get_index(doc->root, (size_t)-1) == NULL, "huge index returns NULL");
    yaml_destroy(doc);
    PASS();
}

static void fill_alpha(char *dst, size_t n, int seed)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)('a' + (i + (size_t)seed) % 26);
    dst[n] = '\0';
}

static void test_long_scan(void)
{
    TEST("Scanner buffers grow past initial capacity");
    /* Every field below exceeds the initial capacity of the scanner that
     * reads it (tag/anchor 64, quoted 128, plain 256), so the shared
     * reserve helper must grow the buffer without corrupting content. */
    char tag[81];
    char anchor[81];
    char plain[301];
    char quoted[201];
    fill_alpha(tag, 80, 0);
    fill_alpha(anchor, 80, 3);
    fill_alpha(plain, 300, 1);
    fill_alpha(quoted, 200, 2);

    char yaml[1024];
    int n = snprintf(yaml, sizeof(yaml), "tagged: !!%s &%s %s\nquoted: \"%s\"\n", tag, anchor,
                     plain, quoted);
    ASSERT(n > 0 && (size_t)n < sizeof(yaml), "test input must fit");

    yaml_document_t *doc = yaml_create();
    int rc = yaml_parse_string(doc, yaml, (size_t)n);
    ASSERT(rc == 0, "long-input parse should succeed");

    struct yaml_node *tagged = yaml_get(doc->root, "tagged");
    ASSERT(tagged != NULL, "tagged key should exist");
    ASSERT(tagged->tag != NULL && strcmp(tagged->tag, tag) == 0,
           "80-byte tag must survive buffer growth");
    ASSERT(tagged->anchor_name != NULL && strcmp(tagged->anchor_name, anchor) == 0,
           "80-byte anchor must survive buffer growth");
    ASSERT(strcmp(yaml_as_string(tagged, ""), plain) == 0,
           "300-byte plain scalar must survive buffer growth");

    struct yaml_node *qn = yaml_get(doc->root, "quoted");
    ASSERT(qn != NULL, "quoted key should exist");
    ASSERT(strcmp(yaml_as_string(qn, ""), quoted) == 0,
           "200-byte quoted scalar must survive buffer growth");

    yaml_destroy(doc);
    PASS();
}

/* 映射装配的终点槽回归（0.1.20 r141）。yaml_size()/free_node() 以首个
 * key == NULL 判终点，装配器若把条目写到容量上限，扫描就会越过分配块读
 * 堆残留并当 key 解引用——llm_d 的 16 键 model.yaml 行即此崩。断言容量
 * 边界（等于/略多/略少于倍增后的容量）两侧都留得住终点槽。 */
static void test_map_slot_bounds(void)
{
    static const size_t sizes[] = {8, 9, 15, 16, 17, 32, 33};
    TEST("Mapping terminal slot at capacity bounds");
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        char yaml[4096];
        int w = snprintf(yaml, sizeof(yaml), "root:\n");
        for (size_t i = 0; i < n && w > 0 && (size_t)w < sizeof(yaml); i++)
            w += snprintf(yaml + w, sizeof(yaml) - (size_t)w, "  k%zu: v%zu\n", i, i);
        ASSERT(w > 0 && (size_t)w < sizeof(yaml), "test input must fit");

        yaml_document_t *doc = yaml_create();
        ASSERT(doc != NULL, "yaml_create returned NULL");
        ASSERT(yaml_parse_string(doc, yaml, (size_t)w) == 0, "parse should succeed");

        struct yaml_node *map = yaml_get(doc->root, "root");
        ASSERT(map != NULL, "mapping key should exist");
        ASSERT(yaml_size(map) == n, "entry count must equal keys written");

        char last[32];
        snprintf(last, sizeof(last), "k%zu", n - 1);
        struct yaml_node *tail = yaml_get(map, last);
        ASSERT(tail != NULL, "last key readable");
        snprintf(last, sizeof(last), "v%zu", n - 1);
        ASSERT(strcmp(yaml_as_string(tail, ""), last) == 0, "last value intact");

        yaml_destroy(doc);
    }
    PASS();
}

/* 现场形态：同一行重复 16 次 `capabilities`，条目数恰好等于容量，
 * 终点槽被占满即崩（llm_d 的 model.yaml 行）。 */
static void test_dup_entries(void)
{
    TEST("Repeated key fills to capacity");
    char yaml[1024];
    int w = snprintf(yaml, sizeof(yaml), "root:\n");
    for (int i = 0; i < 16 && w > 0; i++)
        w += snprintf(yaml + w, sizeof(yaml) - (size_t)w, "  capabilities: %d\n", i);
    ASSERT(w > 0 && (size_t)w < sizeof(yaml), "test input must fit");

    yaml_document_t *doc = yaml_create();
    ASSERT(doc != NULL, "yaml_create returned NULL");
    ASSERT(yaml_parse_string(doc, yaml, (size_t)w) == 0, "parse should succeed");

    struct yaml_node *map = yaml_get(doc->root, "root");
    ASSERT(map != NULL, "mapping key should exist");
    ASSERT(yaml_size(map) == 16, "duplicates kept as separate entries");
    ASSERT(yaml_get(map, "capabilities") != NULL, "repeated key readable");

    yaml_destroy(doc);
    PASS();
}

int main(void)
{
    printf("\n=== YAML Minimal Parser Unit Tests ===\n\n");

    test_create_destroy();
    test_parse_empty();
    test_parse_scalar();
    test_parse_sequence();
    test_null_lookup();
    test_null_document_parse();
    test_null_input_parse();
    test_destroy_null();
    test_key_with_null_value();
    test_dump_scalar();
    test_dump_sequence();
    test_multi_document();
    test_sequence_out_of_bounds();
    test_double_parse();
    test_int_parse();
    test_bool_parse();
    test_string_parse();
    test_plain_scalar_with_colon();
    test_quoted_double();
    test_has_key_null_node();
    test_sequence_get_index_negative();
    test_long_scan();
    test_map_slot_bounds();
    test_dup_entries();

    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
