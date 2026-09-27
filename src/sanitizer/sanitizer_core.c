// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file sanitizer_core.c
 * @brief Input sanitizer core implementation.
 */

#include "sanitizer.h"
#include "sanitizer_cache.h"
#include "sanitizer_rules.h"
#include "utils/cupolas_utils.h"
#include "airy_memory.h"

/* Ensure logging macros are available */
#ifndef LOG_ERROR
#include "logging.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MAX_LENGTH 65536

struct sanitizer {
    sanitizer_rules_t *rules;
    sanitizer_cache_t *cache;
    cupolas_rwlock_t lock;
    cupolas_atomic64_t total_sanitized;
    cupolas_atomic64_t total_rejected;
};

void sanitizer_default_context(sanitize_context_t *ctx)
{
    if (!ctx)
        return;

    __builtin_memset(ctx, 0, sizeof(sanitize_context_t));
    ctx->level = SANITIZE_LEVEL_MEDIUM;
    ctx->max_length = DEFAULT_MAX_LENGTH;
    ctx->allow_html = false;
    ctx->allow_sql = false;
    ctx->allow_shell = false;
    ctx->allow_path = false;
}

sanitizer_t *sanitizer_create(const char *rules_path)
{
    sanitizer_t *san = (sanitizer_t *)cupolas_mem_alloc(sizeof(sanitizer_t));
    if (!san)
        return NULL;

    __builtin_memset(san, 0, sizeof(sanitizer_t));

    if (cupolas_rwlock_init(&san->lock) != cupolas_OK) {
        cupolas_mem_free(san);
        return NULL;
    }

    san->rules = sanitizer_rules_create(rules_path);
    if (!san->rules) {
        cupolas_rwlock_destroy(&san->lock);
        cupolas_mem_free(san);
        return NULL;
    }

    san->cache = sanitizer_cache_create(1024);
    if (!san->cache) {
        sanitizer_rules_destroy(san->rules);
        cupolas_rwlock_destroy(&san->lock);
        cupolas_mem_free(san);
        return NULL;
    }

    return san;
}

void sanitizer_destroy(sanitizer_t *sanitizer)
{
    if (!sanitizer)
        return;

    cupolas_rwlock_wrlock(&sanitizer->lock);

    if (sanitizer->rules) {
        sanitizer_rules_destroy(sanitizer->rules);
    }
    if (sanitizer->cache) {
        sanitizer_cache_destroy(sanitizer->cache);
    }

    cupolas_rwlock_unlock(&sanitizer->lock);
    cupolas_rwlock_destroy(&sanitizer->lock);
    cupolas_mem_free(sanitizer);
}

static bool is_html_danger(char c, const sanitize_context_t *ctx)
{
    if (ctx->allow_html)
        return false;
    return (c == '<' || c == '>');
}

static bool is_sql_danger(char c, const sanitize_context_t *ctx)
{
    if (ctx->allow_sql)
        return false;
    return (c == '\'' || c == '"' || c == ';');
}

static bool is_shell_danger(char c, const sanitize_context_t *ctx)
{
    if (ctx->allow_shell)
        return false;
    return (c == '|' || c == '&' || c == '$' || c == '`' || c == '(' || c == ')' || c == '{' ||
            c == '}');
}

static bool is_path_danger(char c, char prev_char, const sanitize_context_t *ctx)
{
    if (ctx->allow_path)
        return false;
    return (c == '\\' || (c == '.' && prev_char == '.'));
}

static bool is_ctrl_danger(char c)
{
    unsigned char uc = (unsigned char)c;
    return (uc < 0x20 && c != '\t' && c != '\n' && c != '\r');
}

/*
 * Character-class danger detection is deliberately independent of the
 * sanitize level: the level selects the enforcement strategy (escape,
 * whitelist, reject) while the allow_* flags select which character
 * classes are acceptable.
 */
static bool has_danger_chars(const char *input, const sanitize_context_t *ctx)
{
    if (!input)
        return false;

    char prev_char = '\0';
    const char *p = input;

    while (*p) {
        char c = *p;

        if (is_html_danger(c, ctx))
            return true;
        if (is_sql_danger(c, ctx))
            return true;
        if (is_shell_danger(c, ctx))
            return true;
        if (is_path_danger(c, prev_char, ctx))
            return true;
        if (is_ctrl_danger(c))
            return true;

        prev_char = c;
        p++;
    }

    return false;
}

/*
 * HIGH level whitelist: printable ASCII text plus common punctuation.
 * Quotes, HTML/shell metacharacters, control characters, non-ASCII bytes
 * and any other byte outside the set are rejected outright.
 */
static bool is_whitelisted(const char *input)
{
    if (!input)
        return false;

    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        unsigned char c = *p;

        if (c >= 0x80)
            return false;
        if (isalnum(c))
            continue;

        switch (c) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case '.':
        case ',':
        case ':':
        case ';':
        case '_':
        case '@':
        case '#':
        case '-':
        case '+':
        case '/':
        case '=':
        case '?':
        case '!':
        case '(':
        case ')':
            continue;
        default:
            return false;
        }
    }

    return true;
}

static bool try_escape_html(char c, char *output, size_t *out_pos, size_t output_size,
                            const sanitize_context_t *ctx)
{
    if (ctx->allow_html)
        return false;

    if (c == '<') {
        if (*out_pos + 4 >= output_size)
            return false;
        __builtin_memcpy(output + *out_pos, "&lt;", 4);
        *out_pos += 4;
        return true;
    }
    if (c == '>') {
        if (*out_pos + 4 >= output_size)
            return false;
        __builtin_memcpy(output + *out_pos, "&gt;", 4);
        *out_pos += 4;
        return true;
    }
    if (c == '&') {
        if (*out_pos + 5 >= output_size)
            return false;
        __builtin_memcpy(output + *out_pos, "&amp;", 5);
        *out_pos += 5;
        return true;
    }
    return false;
}

static bool try_escape_sql(char c, char *output, size_t *out_pos, size_t output_size,
                           const sanitize_context_t *ctx)
{
    if (ctx->allow_sql)
        return false;

    if (c == '\'') {
        if (*out_pos + 2 >= output_size)
            return false;
        output[(*out_pos)++] = '\'';
        output[(*out_pos)++] = '\'';
        return true;
    }
    return false;
}

static bool is_shell_special(char c)
{
    return (c == '\\' || c == '\'' || c == '\"' || c == '`' || c == '$' || c == '|' || c == '&' ||
            c == ';' || c == '(' || c == ')' || c == '{' || c == '}');
}

static bool try_escape_shell(char c, char *output, size_t *out_pos, size_t output_size,
                             const sanitize_context_t *ctx)
{
    if (ctx->allow_shell)
        return false;

    if (is_shell_special(c)) {
        if (*out_pos + 2 >= output_size)
            return false;
        output[(*out_pos)++] = '\\';
        output[(*out_pos)++] = c;
        return true;
    }
    return false;
}

static int escape_rules(const char *input, char *output, size_t output_size,
                        const sanitize_context_t *ctx)
{
    if (!input || !output || output_size == 0)
        return cupolas_ERROR_INVALID_ARG;

    size_t in_len = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        char c = input[i];

        if (try_escape_html(c, output, &out_pos, output_size, ctx))
            continue;
        if (try_escape_sql(c, output, &out_pos, output_size, ctx))
            continue;
        if (try_escape_shell(c, output, &out_pos, output_size, ctx))
            continue;

        if (c == '<' || c == '>' || c == '&' || c == '"' || c == '\'' || c == '|' || c == '$' ||
            c == '`' || c == '\\' || c == ';') {
            if (out_pos + 1 < output_size) {
                output[out_pos++] = '?';
            }
            continue;
        }

        if (out_pos + 1 < output_size) {
            output[out_pos++] = c;
        }
    }

    output[out_pos < output_size ? out_pos : output_size - 1] = '\0';
    return cupolas_OK;
}

sanitize_result_t sanitizer_sanitize(sanitizer_t *sanitizer, const char *input, char *output,
                                     size_t output_size, const sanitize_context_t *ctx)
{
    if (!sanitizer || !input || !output || output_size == 0) {
        AIRY_LOG_ERROR("sanitizer_sanitize: NULL/invalid parameter - sanitizer=%p, input=%p, output=%p, "
                  "output_size=%zu",
                  (void *)sanitizer, (void *)input, (void *)output, output_size);
        return SANITIZE_ERROR;
    }

    sanitize_context_t default_ctx;
    if (!ctx) {
        sanitizer_default_context(&default_ctx);
        ctx = &default_ctx;
    }

    output[0] = '\0';

    size_t input_len = strlen(input);

    if (ctx->level >= SANITIZE_LEVEL_MAX) {
        AIRY_LOG_WARN("sanitizer_sanitize: rejected by MAX level - input_len=%zu", input_len);
        cupolas_atomic_add64(&sanitizer->total_rejected, 1);
        return SANITIZE_REJECTED;
    }

    if (ctx->max_length > 0 && input_len > ctx->max_length) {
        AIRY_LOG_WARN("sanitizer_sanitize: input truncated/rejected - input_len=%zu, max_length=%zu",
                 input_len, ctx->max_length);
        cupolas_atomic_add64(&sanitizer->total_rejected, 1);
        return SANITIZE_REJECTED;
    }

    cupolas_rwlock_rdlock(&sanitizer->lock);

    bool cached = false;
    char *cached_output = sanitizer_cache_get(sanitizer->cache, input, ctx->level);
    if (cached_output) {
        AIRY_STRNCPY_TERM(output, cached_output, output_size);
        cupolas_mem_free(cached_output);
        cached = true;
    }
    cupolas_rwlock_unlock(&sanitizer->lock);

    if (cached) {
        cupolas_atomic_add64(&sanitizer->total_sanitized, 1);
        return (strcmp(output, input) != 0) ? SANITIZE_MODIFIED : SANITIZE_OK;
    }

    if (ctx->level == SANITIZE_LEVEL_NONE) {
        AIRY_STRNCPY_TERM(output, input, output_size);
    } else if (ctx->level >= SANITIZE_LEVEL_HIGH) {
        if (!is_whitelisted(input)) {
            AIRY_LOG_WARN("sanitizer_sanitize: rejected by whitelist - input_len=%zu, level=%d",
                     input_len, (int)ctx->level);
            cupolas_atomic_add64(&sanitizer->total_rejected, 1);
            return SANITIZE_REJECTED;
        }
        AIRY_STRNCPY_TERM(output, input, output_size);
    } else if (has_danger_chars(input, ctx)) {
        AIRY_LOG_WARN("sanitizer_sanitize: malicious input detected - input_len=%zu, level=%d",
                 input_len, (int)ctx->level);
        if (escape_rules(input, output, output_size, ctx) != cupolas_OK) {
            AIRY_LOG_ERROR("sanitizer_sanitize: escape rules failed for input_len=%zu, output_size=%zu",
                      input_len, output_size);
            cupolas_atomic_add64(&sanitizer->total_rejected, 1);
            return SANITIZE_ERROR;
        }
    } else {
        AIRY_STRNCPY_TERM(output, input, output_size);
    }

    /* MEDIUM adds pattern-matching rules on top of character escaping.
     * A rule without replacement rejects the whole input (fail-closed). */
    if (ctx->level >= SANITIZE_LEVEL_MEDIUM && ctx->level < SANITIZE_LEVEL_HIGH &&
        sanitizer->rules) {
        char *tmp = (char *)AIRY_MALLOC(output_size);
        if (!tmp) {
            AIRY_LOG_ERROR("sanitizer_sanitize: rule buffer allocation failed - output_size=%zu",
                      output_size);
            cupolas_atomic_add64(&sanitizer->total_rejected, 1);
            return SANITIZE_ERROR;
        }

        int rrc = sanitizer_rules_apply(sanitizer->rules, output, tmp, output_size);
        if (rrc != cupolas_OK) {
            AIRY_FREE(tmp);
            cupolas_atomic_add64(&sanitizer->total_rejected, 1);
            return SANITIZE_REJECTED;
        }
        AIRY_STRNCPY_TERM(output, tmp, output_size);
        AIRY_FREE(tmp);
    }

    cupolas_rwlock_wrlock(&sanitizer->lock);
    sanitizer_cache_put(sanitizer->cache, input, output, ctx->level);
    cupolas_rwlock_unlock(&sanitizer->lock);

    cupolas_atomic_add64(&sanitizer->total_sanitized, 1);
    return (strcmp(output, input) != 0) ? SANITIZE_MODIFIED : SANITIZE_OK;
}

bool sanitizer_is_safe(sanitizer_t *sanitizer, const char *input, const sanitize_context_t *ctx)
{
    if (!sanitizer || !input) {
        AIRY_LOG_ERROR("sanitizer_is_safe: NULL parameter - sanitizer=%p, input=%p", (void *)sanitizer,
                  (void *)input);
        return false;
    }

    sanitize_context_t default_ctx;
    if (!ctx) {
        sanitizer_default_context(&default_ctx);
        ctx = &default_ctx;
    }

    size_t input_len = strlen(input);
    if (ctx->max_length > 0 && input_len > ctx->max_length) {
        return false;
    }

    if (ctx->level >= SANITIZE_LEVEL_MAX)
        return false;
    if (ctx->level == SANITIZE_LEVEL_NONE)
        return true;
    if (ctx->level >= SANITIZE_LEVEL_HIGH)
        return is_whitelisted(input);

    return !has_danger_chars(input, ctx);
}

int sanitizer_escape_html(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        AIRY_LOG_ERROR(
            "sanitizer_escape_html: NULL/invalid parameter - input=%p, output=%p, output_size=%zu",
            (void *)input, (void *)output, output_size);
        return cupolas_ERROR_INVALID_ARG;
    }

    size_t in_len = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len && out_pos < output_size - 1; i++) {
        char c = input[i];
        switch (c) {
        case '<':
            if (out_pos + 4 >= output_size)
                goto overflow;
            __builtin_memcpy(output + out_pos, "&lt;", 4);
            out_pos += 4;
            break;
        case '>':
            if (out_pos + 4 >= output_size)
                goto overflow;
            __builtin_memcpy(output + out_pos, "&gt;", 4);
            out_pos += 4;
            break;
        case '&':
            if (out_pos + 5 >= output_size)
                goto overflow;
            __builtin_memcpy(output + out_pos, "&amp;", 5);
            out_pos += 5;
            break;
        case '"':
            if (out_pos + 6 >= output_size)
                goto overflow;
            __builtin_memcpy(output + out_pos, "&quot;", 6);
            out_pos += 6;
            break;
        case '\'':
            if (out_pos + 6 >= output_size)
                goto overflow;
            __builtin_memcpy(output + out_pos, "&#39;", 5);
            out_pos += 5;
            break;
        default:
            output[out_pos++] = c;
            break;
        }
    }

    output[out_pos] = '\0';
    return cupolas_OK;

overflow:
    AIRY_LOG_WARN("sanitizer_escape_html: output buffer overflow - input_len=%zu, output_size=%zu",
             strlen(input), output_size);
    output[out_pos] = '\0';
    return cupolas_ERROR_OVERFLOW;
}

int sanitizer_escape_sql(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        AIRY_LOG_ERROR(
            "sanitizer_escape_sql: NULL/invalid parameter - input=%p, output=%p, output_size=%zu",
            (void *)input, (void *)output, output_size);
        return cupolas_ERROR_INVALID_ARG;
    }

    size_t in_len = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len && out_pos < output_size - 1; i++) {
        char c = input[i];
        switch (c) {
        case '\'':
            if (out_pos + 2 >= output_size)
                goto overflow;
            output[out_pos++] = '\'';
            output[out_pos++] = '\'';
            break;
        case '\\':
            if (out_pos + 2 >= output_size)
                goto overflow;
            output[out_pos++] = '\\';
            output[out_pos++] = '\\';
            break;
        case '\0':
            if (out_pos + 2 >= output_size)
                goto overflow;
            output[out_pos++] = '\\';
            output[out_pos++] = '0';
            break;
        case '\n':
            if (out_pos + 2 >= output_size)
                goto overflow;
            output[out_pos++] = '\\';
            output[out_pos++] = 'n';
            break;
        case '\r':
            if (out_pos + 2 >= output_size)
                goto overflow;
            output[out_pos++] = '\\';
            output[out_pos++] = 'r';
            break;
        default:
            output[out_pos++] = c;
            break;
        }
    }

    output[out_pos] = '\0';
    return cupolas_OK;

overflow:
    AIRY_LOG_WARN("sanitizer_escape_sql: output buffer overflow - input_len=%zu, output_size=%zu",
             strlen(input), output_size);
    output[out_pos] = '\0';
    return cupolas_ERROR_OVERFLOW;
}

int sanitizer_escape_shell(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        AIRY_LOG_ERROR(
            "sanitizer_escape_shell: NULL/invalid parameter - input=%p, output=%p, output_size=%zu",
            (void *)input, (void *)output, output_size);
        return cupolas_ERROR_INVALID_ARG;
    }

    size_t in_len = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len && out_pos < output_size - 1; i++) {
        char c = input[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '/') {
            output[out_pos++] = c;
        } else {
            if (out_pos + 4 >= output_size)
                goto overflow;
            out_pos +=
                snprintf(output + out_pos, output_size - out_pos, "\\x%02x", (unsigned char)c);
        }
    }

    output[out_pos] = '\0';
    return cupolas_OK;

overflow:
    AIRY_LOG_WARN("sanitizer_escape_shell: output buffer overflow - input_len=%zu, output_size=%zu",
             strlen(input), output_size);
    output[out_pos] = '\0';
    return cupolas_ERROR_OVERFLOW;
}

int sanitizer_escape_path(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size == 0) {
        AIRY_LOG_ERROR(
            "sanitizer_escape_path: NULL/invalid parameter - input=%p, output=%p, output_size=%zu",
            (void *)input, (void *)output, output_size);
        return cupolas_ERROR_INVALID_ARG;
    }

    size_t in_len = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len && out_pos < output_size - 1; i++) {
        char c = input[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '/' ||
            c == '\\' || c == ':') {
            output[out_pos++] = c;
        } else {
            if (out_pos + 4 >= output_size)
                goto overflow;
            out_pos +=
                snprintf(output + out_pos, output_size - out_pos, "%%%02X", (unsigned char)c);
        }
    }

    output[out_pos] = '\0';
    return cupolas_OK;

overflow:
    AIRY_LOG_WARN("sanitizer_escape_path: output buffer overflow - input_len=%zu, output_size=%zu",
             strlen(input), output_size);
    output[out_pos] = '\0';
    return cupolas_ERROR_OVERFLOW;
}

int sanitizer_add_rule(sanitizer_t *sanitizer, const char *pattern, const char *replacement)
{
    if (!sanitizer || !pattern) {
        AIRY_LOG_ERROR("sanitizer_add_rule: NULL parameter - sanitizer=%p, pattern=%p",
                  (void *)sanitizer, (void *)pattern);
        return cupolas_ERROR_INVALID_ARG;
    }

    cupolas_rwlock_wrlock(&sanitizer->lock);
    int ret = sanitizer_rules_add(sanitizer->rules, pattern, replacement);
    if (ret != cupolas_OK) {
        AIRY_LOG_ERROR("sanitizer_add_rule: pattern matching error - pattern=%s, ret=%d", pattern, ret);
    }
    sanitizer_cache_clear(sanitizer->cache);
    cupolas_rwlock_unlock(&sanitizer->lock);

    return ret;
}

void sanitizer_clear_rules(sanitizer_t *sanitizer)
{
    if (!sanitizer)
        return;

    cupolas_rwlock_wrlock(&sanitizer->lock);
    sanitizer_rules_clear(sanitizer->rules);
    sanitizer_cache_clear(sanitizer->cache);
    cupolas_rwlock_unlock(&sanitizer->lock);
}
