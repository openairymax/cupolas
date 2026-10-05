// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * sanitizer_rules.c - Sanitizer Rules Manager Implementation
 */

/**
 * @file sanitizer_rules.c
 * @brief Sanitizer Rules Manager Implementation
 * @author SPHARX Ltd. - Airymax Team
 */

#include "sanitizer_rules.h"
#include "security/cupolas_error.h"

#include "utils/cupolas_utils.h"
#include "airy_memory.h"

#include <stdlib.h>
#include <string.h>

struct sanitize_rule {
    char *pattern;
    char *replacement;
    struct sanitize_rule *next;
};

struct sanitizer_rules {
    struct sanitize_rule *head;
    size_t count;
    airy_mtx_t lock;
};

sanitizer_rules_t *sanitizer_rules_create(const char *rules_path)
{
    sanitizer_rules_t *rules = (sanitizer_rules_t *)AIRY_CALLOC(1, sizeof(sanitizer_rules_t));
    if (!rules)
        return NULL;

    __builtin_memset(rules, 0, sizeof(sanitizer_rules_t));

    if (airy_mtx_init(&rules->lock) != cupolas_OK) {
        AIRY_FREE(rules);
        return NULL;
    }

    return rules;
}

void sanitizer_rules_destroy(sanitizer_rules_t *rules)
{
    if (!rules)
        return;

    airy_mtx_lock(&rules->lock);

    struct sanitize_rule *rule = rules->head;
    while (rule) {
        struct sanitize_rule *next = rule->next;
        AIRY_FREE(rule->pattern);
        AIRY_FREE(rule->replacement);
        AIRY_FREE(rule);
        rule = next;
    }

    airy_mtx_unlock(&rules->lock);
    airy_mtx_destroy(&rules->lock);
    AIRY_FREE(rules);
}

int sanitizer_rules_add(sanitizer_rules_t *rules, const char *pattern, const char *replacement)
{
    if (!rules || !pattern)
        return cupolas_ERROR_INVALID_ARG;

    struct sanitize_rule *rule =
        (struct sanitize_rule *)AIRY_CALLOC(1, sizeof(struct sanitize_rule));
    if (!rule)
        return cupolas_ERROR_NO_MEMORY;

    __builtin_memset(rule, 0, sizeof(struct sanitize_rule));

    rule->pattern = AIRY_STRDUP(pattern);
    if (!rule->pattern) {
        AIRY_FREE(rule);
        return cupolas_ERROR_NO_MEMORY;
    }

    if (replacement) {
        rule->replacement = AIRY_STRDUP(replacement);
        if (!rule->replacement) {
            AIRY_FREE(rule->pattern);
            AIRY_FREE(rule);
            return cupolas_ERROR_NO_MEMORY;
        }
    }

    airy_mtx_lock(&rules->lock);

    rule->next = rules->head;
    rules->head = rule;
    rules->count++;

    airy_mtx_unlock(&rules->lock);

    return cupolas_OK;
}

int sanitizer_rules_apply(sanitizer_rules_t *rules, const char *input, char *output,
                          size_t output_size)
{
    if (!rules || !input || !output || output_size == 0) {
        return cupolas_ERROR_INVALID_ARG;
    }

    airy_mtx_lock(&rules->lock);

    AIRY_STRNCPY_TERM(output, input, output_size);

    struct sanitize_rule *rule = rules->head;
    while (rule) {
        if (strstr(output, rule->pattern) != NULL) {
            if (rule->replacement) {
                char *found = strstr(output, rule->pattern);
                if (found) {
                    size_t pat_len = strlen(rule->pattern);
                    size_t rep_len = strlen(rule->replacement);
                    size_t out_len = strlen(output);

                    if (out_len - pat_len + rep_len < output_size) {
                        __builtin_memmove(found + rep_len, found + pat_len,
                                          out_len - (found - output) - pat_len);
                        __builtin_memcpy(found, rule->replacement, rep_len);
                    }
                }
            } else {
                airy_mtx_unlock(&rules->lock);
                return cupolas_ERROR_UNKNOWN;
            }
        }
        rule = rule->next;
    }

    airy_mtx_unlock(&rules->lock);

    return cupolas_OK;
}

void sanitizer_rules_clear(sanitizer_rules_t *rules)
{
    if (!rules)
        return;

    airy_mtx_lock(&rules->lock);

    struct sanitize_rule *rule = rules->head;
    while (rule) {
        struct sanitize_rule *next = rule->next;
        AIRY_FREE(rule->pattern);
        AIRY_FREE(rule->replacement);
        AIRY_FREE(rule);
        rule = next;
    }

    rules->head = NULL;
    rules->count = 0;

    airy_mtx_unlock(&rules->lock);
}
