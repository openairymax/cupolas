// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * sanitizer_cache.c - Sanitizer Cache Implementation
 */

/**
 * @file sanitizer_cache.c
 * @brief Level-scoped key policy layered on the shared cache atom.
 * @author SPHARX Ltd. - Airymax Team
 *
 * The sanitizer only owns the *policy* of this cache: how a lookup key is
 * composed from (level, input) and how long a sanitized result stays valid.
 * The bounded LRU store itself is the cache_common atom (commons/utils/cache),
 * so the eviction, locking and TTL mechanics live in exactly one place.
 */

#include "sanitizer_cache.h"

#include "airy_memory.h"
#include "cache_common.h"

#include <stdio.h>
#include <string.h>

#define SANITIZER_CACHE_TTL_SEC 60
#define SANITIZER_CACHE_CAP_DEF 1024

struct sanitizer_cache {
    cache_t inner;
};

static char *sanitizer_key_make(const char *input, sanitize_level_t level)
{
    size_t len = strlen(input) + 16;
    char *key = (char *)AIRY_CALLOC(1, len);
    if (!key)
        return NULL;

    snprintf(key, len, "%d:%s", (int)level, input);
    return key;
}

sanitizer_cache_t *sanitizer_cache_create(size_t capacity)
{
    sanitizer_cache_t *cache = (sanitizer_cache_t *)AIRY_CALLOC(1, sizeof(sanitizer_cache_t));
    if (!cache)
        return NULL;

    size_t cap = capacity > 0 ? capacity : SANITIZER_CACHE_CAP_DEF;
    cache->inner = cache_create_string_cache(cap, SANITIZER_CACHE_TTL_SEC);
    if (!cache->inner) {
        AIRY_FREE(cache);
        return NULL;
    }

    return cache;
}

void sanitizer_cache_destroy(sanitizer_cache_t *cache)
{
    if (!cache)
        return;

    cache_destroy(cache->inner);
    AIRY_FREE(cache);
}

void sanitizer_cache_clear(sanitizer_cache_t *cache)
{
    if (cache)
        cache_clear(cache->inner);
}

char *sanitizer_cache_get(sanitizer_cache_t *cache, const char *input, sanitize_level_t level)
{
    if (!cache || !input)
        return NULL;

    char *key = sanitizer_key_make(input, level);
    if (!key)
        return NULL;

    char *value = NULL;
    int hit = cache_get_string(cache->inner, key, &value);
    AIRY_FREE(key);

    return hit == 1 ? value : NULL;
}

void sanitizer_cache_put(sanitizer_cache_t *cache, const char *input, const char *output,
                         sanitize_level_t level)
{
    if (!cache || !input || !output)
        return;

    char *key = sanitizer_key_make(input, level);
    if (!key)
        return;

    cache_put_string(cache->inner, key, output);
    AIRY_FREE(key);
}
