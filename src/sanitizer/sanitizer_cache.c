// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * sanitizer_cache.c - Sanitizer Cache Implementation
 */

/**
 * @file sanitizer_cache.c
 * @brief Sanitizer Cache Implementation
 * @author SPHARX Ltd. - Airymax Team
 */

#include "platform.h"
#include "sanitizer_cache.h"
#include "security/cupolas_error.h"

#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_TTL_MS 60000

typedef struct cache_entry {
    char *key;
    char *value;
    uint64_t timestamp_ms;
    uint64_t last_access_ms;
    struct cache_entry *next;
    struct cache_entry *prev;
    struct cache_entry *lru_next;
    struct cache_entry *lru_prev;
} cache_entry_t;

struct sanitizer_cache {
    cache_entry_t **buckets;
    size_t bucket_count;
    size_t size;
    size_t capacity;
    cache_entry_t lru_head;
    cache_entry_t lru_tail;
    airy_mtx_t lock;
};

static uint32_t hash_key(const char *key)
{
    uint32_t hash = 5381;
    while (*key) {
        hash = ((hash << 5) + hash) + (unsigned char)*key++;
    }
    return hash;
}

static char *build_key(const char *input, sanitize_level_t level)
{
    size_t len = strlen(input) + 16;
    char *key = (char *)AIRY_CALLOC(1, len);
    if (!key)
        return NULL;
    snprintf(key, len, "%d:%s", (int)level, input);
    return key;
}

static void lru_init(sanitizer_cache_t *cache)
{
    cache->lru_head.lru_next = &cache->lru_tail;
    cache->lru_head.lru_prev = NULL;
    cache->lru_tail.lru_next = NULL;
    cache->lru_tail.lru_prev = &cache->lru_head;
}

static void lru_add(sanitizer_cache_t *cache, cache_entry_t *entry)
{
    entry->lru_next = cache->lru_head.lru_next;
    entry->lru_prev = &cache->lru_head;
    cache->lru_head.lru_next->lru_prev = entry;
    cache->lru_head.lru_next = entry;
}

static void lru_remove(cache_entry_t *entry)
{
    entry->lru_prev->lru_next = entry->lru_next;
    entry->lru_next->lru_prev = entry->lru_prev;
}

static void lru_touch(sanitizer_cache_t *cache, cache_entry_t *entry)
{
    lru_remove(entry);
    lru_add(cache, entry);
}

static void lru_evict(sanitizer_cache_t *cache)
{
    while (cache->size >= cache->capacity && cache->lru_tail.lru_prev != &cache->lru_head) {
        cache_entry_t *victim = cache->lru_tail.lru_prev;
        lru_remove(victim);

        uint32_t hash = hash_key(victim->key);
        size_t idx = hash % cache->bucket_count;
        cache_entry_t **ptr = &cache->buckets[idx];
        while (*ptr && *ptr != victim) {
            ptr = &(*ptr)->next;
        }
        if (*ptr == victim) {
            *ptr = victim->next;
        }

        AIRY_FREE(victim->key);
        AIRY_FREE(victim->value);
        AIRY_FREE(victim);
        cache->size--;
    }
}

sanitizer_cache_t *sanitizer_cache_create(size_t capacity)
{
    sanitizer_cache_t *cache = (sanitizer_cache_t *)AIRY_CALLOC(1, sizeof(sanitizer_cache_t));
    if (!cache)
        return NULL;

    __builtin_memset(cache, 0, sizeof(sanitizer_cache_t));
    cache->capacity = capacity > 0 ? capacity : 1024;
    cache->bucket_count = cache->capacity / 4;
    if (cache->bucket_count < 16)
        cache->bucket_count = 16;

    cache->buckets =
        (cache_entry_t **)AIRY_CALLOC(1, cache->bucket_count * sizeof(cache_entry_t *));
    if (!cache->buckets) {
        AIRY_FREE(cache);
        return NULL;
    }
    __builtin_memset(cache->buckets, 0, cache->bucket_count * sizeof(cache_entry_t *));

    lru_init(cache);

    if (airy_mtx_init(&cache->lock) != cupolas_OK) {
        AIRY_FREE(cache->buckets);
        AIRY_FREE(cache);
        return NULL;
    }

    return cache;
}

void sanitizer_cache_destroy(sanitizer_cache_t *cache)
{
    if (!cache)
        return;

    airy_mtx_lock(&cache->lock);

    for (size_t i = 0; i < cache->bucket_count; i++) {
        cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            cache_entry_t *next = entry->next;
            AIRY_FREE(entry->key);
            AIRY_FREE(entry->value);
            AIRY_FREE(entry);
            entry = next;
        }
    }

    AIRY_FREE(cache->buckets);

    airy_mtx_unlock(&cache->lock);
    airy_mtx_destroy(&cache->lock);
    AIRY_FREE(cache);
}

void sanitizer_cache_clear(sanitizer_cache_t *cache)
{
    if (!cache)
        return;

    airy_mtx_lock(&cache->lock);

    for (size_t i = 0; i < cache->bucket_count; i++) {
        cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            cache_entry_t *next = entry->next;
            AIRY_FREE(entry->key);
            AIRY_FREE(entry->value);
            AIRY_FREE(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    cache->size = 0;
    lru_init(cache);

    airy_mtx_unlock(&cache->lock);
}

char *sanitizer_cache_get(sanitizer_cache_t *cache, const char *input, sanitize_level_t level)
{
    if (!cache || !input)
        return NULL;

    char *key = build_key(input, level);
    if (!key)
        return NULL;

    airy_mtx_lock(&cache->lock);

    uint32_t hash = hash_key(key);
    size_t idx = hash % cache->bucket_count;

    cache_entry_t *entry = cache->buckets[idx];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            uint64_t now = airy_time_wall_ms();
            if (now - entry->timestamp_ms > CACHE_TTL_MS) {
                airy_mtx_unlock(&cache->lock);
                AIRY_FREE(key);
                return NULL;
            }
            entry->last_access_ms = now;
            lru_touch(cache, entry);
            char *result = AIRY_STRDUP(entry->value);
            airy_mtx_unlock(&cache->lock);
            AIRY_FREE(key);
            return result;
        }
        entry = entry->next;
    }

    airy_mtx_unlock(&cache->lock);
    AIRY_FREE(key);
    return NULL;
}

void sanitizer_cache_put(sanitizer_cache_t *cache, const char *input, const char *output,
                         sanitize_level_t level)
{
    if (!cache || !input || !output)
        return;

    char *key = build_key(input, level);
    if (!key)
        return;

    airy_mtx_lock(&cache->lock);

    uint32_t hash = hash_key(key);
    size_t idx = hash % cache->bucket_count;

    cache_entry_t *entry = cache->buckets[idx];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            AIRY_FREE(entry->value);
            entry->value = AIRY_STRDUP(output);
            entry->timestamp_ms = airy_time_wall_ms();
            entry->last_access_ms = entry->timestamp_ms;
            lru_touch(cache, entry);
            airy_mtx_unlock(&cache->lock);
            AIRY_FREE(key);
            return;
        }
        entry = entry->next;
    }

    if (cache->size >= cache->capacity) {
        lru_evict(cache);
    }

    entry = (cache_entry_t *)AIRY_CALLOC(1, sizeof(cache_entry_t));
    if (!entry) {
        airy_mtx_unlock(&cache->lock);
        AIRY_FREE(key);
        return;
    }

    entry->key = key;
    entry->value = AIRY_STRDUP(output);
    entry->timestamp_ms = airy_time_wall_ms();
    entry->last_access_ms = entry->timestamp_ms;
    entry->next = cache->buckets[idx];
    entry->prev = NULL;
    cache->buckets[idx] = entry;
    lru_add(cache, entry);
    cache->size++;

    airy_mtx_unlock(&cache->lock);
}
