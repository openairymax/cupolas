// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file permission_cache.c
 * @brief Permission cache implementation: hash-based LRU cache.
 */

#include "platform.h"
#include "atomic_compat.h"
#include "airy_memory.h"
#include "permission_cache.h"
#include "security/cupolas_error.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"

#define DEFAULT_BUCKET_COUNT 64
#define MAX_BUCKET_COUNT 4096
#define LOAD_FACTOR_THRESHOLD 0.75

static uint32_t hash_string(const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static char *build_cache_key(const char *agent_id, const char *action, const char *resource,
                             const char *context)
{
    size_t agent_len = agent_id ? strlen(agent_id) : 0;
    size_t action_len = action ? strlen(action) : 0;
    size_t resource_len = resource ? strlen(resource) : 0;
    size_t context_len = context ? strlen(context) : 0;

    size_t total_len = agent_len + 1 + action_len + 1 + resource_len + 1 + context_len + 1;
    char *key = (char *)AIRY_CALLOC(1, total_len);
    if (!key)
        return NULL;

    char *p = key;
    if (agent_id) {
        __builtin_memcpy(p, agent_id, agent_len);
        p += agent_len;
    }
    *p++ = ':';
    if (action) {
        __builtin_memcpy(p, action, action_len);
        p += action_len;
    }
    *p++ = ':';
    if (resource) {
        __builtin_memcpy(p, resource, resource_len);
        p += resource_len;
    }
    *p++ = ':';
    if (context) {
        __builtin_memcpy(p, context, context_len);
        p += context_len;
    }
    *p = '\0';

    return key;
}

static size_t next_power_of_two(size_t n)
{
    size_t power = 1;
    while (power < n) {
        power *= 2;
    }
    return power;
}

cache_manager_t *cache_manager_create(size_t capacity, uint32_t ttl_ms)
{
    if (capacity == 0) {
        capacity = 1024;
    }

    cache_manager_t *cm = (cache_manager_t *)AIRY_CALLOC(1, sizeof(cache_manager_t));
    if (!cm)
        return NULL;

    __builtin_memset(cm, 0, sizeof(cache_manager_t));

    size_t bucket_count = next_power_of_two(capacity / 4);
    if (bucket_count < DEFAULT_BUCKET_COUNT) {
        bucket_count = DEFAULT_BUCKET_COUNT;
    }
    if (bucket_count > MAX_BUCKET_COUNT) {
        bucket_count = MAX_BUCKET_COUNT;
    }

    cm->buckets = (cache_entry_t **)AIRY_CALLOC(1, bucket_count * sizeof(cache_entry_t *));
    if (!cm->buckets) {
        AIRY_FREE(cm);
        return NULL;
    }
    __builtin_memset(cm->buckets, 0, bucket_count * sizeof(cache_entry_t *));

    cm->bucket_count = bucket_count;
    cm->capacity = capacity;
    cm->ttl_ms = ttl_ms;

    if (airy_mtx_init(&cm->lock) != cupolas_OK) {
        AIRY_FREE(cm->buckets);
        AIRY_FREE(cm);
        return NULL;
    }

    return cm;
}

void cache_manager_destroy(cache_manager_t *cm)
{
    if (!cm)
        return;

    airy_mtx_lock(&cm->lock);

    cache_entry_t *entry = cm->head;
    while (entry) {
        cache_entry_t *next = entry->next;
        AIRY_FREE(entry->key);
        AIRY_FREE(entry);
        entry = next;
    }

    AIRY_FREE(cm->buckets);

    airy_mtx_unlock(&cm->lock);
    airy_mtx_destroy(&cm->lock);
    AIRY_FREE(cm);
}

static void move_to_head(cache_manager_t *cm, cache_entry_t *entry)
{
    if (entry == cm->head)
        return;

    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (entry == cm->tail) {
        cm->tail = entry->prev;
    }

    entry->prev = NULL;
    entry->next = cm->head;
    if (cm->head) {
        cm->head->prev = entry;
    }
    cm->head = entry;

    if (!cm->tail) {
        cm->tail = entry;
    }
}

static void remove_entry(cache_manager_t *cm, cache_entry_t *entry)
{
    size_t bucket_idx = entry->hash & (cm->bucket_count - 1);
    cache_entry_t **pp = &cm->buckets[bucket_idx];

    while (*pp) {
        if (*pp == entry) {
            *pp = entry->hnext;
            break;
        }
        pp = &(*pp)->hnext;
    }

    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cm->head = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cm->tail = entry->prev;
    }

    AIRY_FREE(entry->key);
    AIRY_FREE(entry);
    cm->size--;
}

static cache_entry_t *find_entry(cache_manager_t *cm, uint32_t hash, const char *key)
{
    size_t bucket_idx = hash & (cm->bucket_count - 1);
    cache_entry_t *entry = cm->buckets[bucket_idx];

    while (entry) {
        if (entry->hash == hash && strcmp(entry->key, key) == 0) {
            return entry;
        }
        entry = entry->hnext;
    }

    return NULL;
}

int cache_manager_get(cache_manager_t *cm, const char *agent_id, const char *action,
                      const char *resource, const char *context)
{
    /* Contract (permission_cache.h L88): 1=allowed, 0=denied,
     * -1=cache miss or error. Cache miss/error always returns -1, not
     * AIRY_EINVAL, to match the documented API contract. */
    if (!cm)
        return -1;

    char *key = build_cache_key(agent_id, action, resource, context);
    if (!key)
        return -1;

    uint32_t hash = hash_string(key);

    airy_mtx_lock(&cm->lock);

    cache_entry_t *entry = find_entry(cm, hash, key);

    if (entry) {
        if (cm->ttl_ms > 0) {
            uint64_t now = airy_time_wall_ms();
            if (now - entry->timestamp_ms > cm->ttl_ms) {
                remove_entry(cm, entry);
                atomic_fetch_add_64(&cm->miss_count, 1, memory_order_seq_cst);
                airy_mtx_unlock(&cm->lock);
                AIRY_FREE(key);
                return -1;
            }
        }

        move_to_head(cm, entry);
        int result = entry->result;
        atomic_fetch_add_64(&cm->hit_count, 1, memory_order_seq_cst);
        airy_mtx_unlock(&cm->lock);
        AIRY_FREE(key);
        return result;
    }

    atomic_fetch_add_64(&cm->miss_count, 1, memory_order_seq_cst);
    airy_mtx_unlock(&cm->lock);
    AIRY_FREE(key);
    return -1;
}

void cache_manager_put(cache_manager_t *cm, const char *agent_id, const char *action,
                       const char *resource, const char *context, int result)
{
    if (!cm)
        return;

    char *key = build_cache_key(agent_id, action, resource, context);
    if (!key)
        return;

    uint32_t hash = hash_string(key);

    airy_mtx_lock(&cm->lock);

    cache_entry_t *entry = find_entry(cm, hash, key);

    if (entry) {
        entry->result = result;
        entry->timestamp_ms = airy_time_wall_ms();
        move_to_head(cm, entry);
        airy_mtx_unlock(&cm->lock);
        AIRY_FREE(key);
        return;
    }

    while (cm->size >= cm->capacity && cm->tail) {
        remove_entry(cm, cm->tail);
    }

    entry = (cache_entry_t *)AIRY_CALLOC(1, sizeof(cache_entry_t));
    if (!entry) {
        airy_mtx_unlock(&cm->lock);
        AIRY_FREE(key);
        return;
    }

    entry->key = key;
    entry->result = result;
    entry->timestamp_ms = airy_time_wall_ms();
    entry->hash = hash;
    entry->prev = NULL;
    entry->next = cm->head;
    entry->hnext = NULL;

    if (cm->head) {
        cm->head->prev = entry;
    }
    cm->head = entry;
    if (!cm->tail) {
        cm->tail = entry;
    }

    size_t bucket_idx = hash & (cm->bucket_count - 1);
    entry->hnext = cm->buckets[bucket_idx];
    cm->buckets[bucket_idx] = entry;

    cm->size++;

    airy_mtx_unlock(&cm->lock);
}

void cache_manager_clear(cache_manager_t *cm)
{
    if (!cm)
        return;

    airy_mtx_lock(&cm->lock);

    cache_entry_t *entry = cm->head;
    while (entry) {
        cache_entry_t *next = entry->next;
        AIRY_FREE(entry->key);
        AIRY_FREE(entry);
        entry = next;
    }

    __builtin_memset(cm->buckets, 0, cm->bucket_count * sizeof(cache_entry_t *));
    cm->head = NULL;
    cm->tail = NULL;
    cm->size = 0;

    airy_mtx_unlock(&cm->lock);
}

void cache_manager_stats(cache_manager_t *cm, uint64_t *hit_count, uint64_t *miss_count)
{
    if (!cm) {
        if (hit_count)
            *hit_count = 0;
        if (miss_count)
            *miss_count = 0;
        return;
    }

    if (hit_count)
        *hit_count = atomic_load_64(&cm->hit_count, memory_order_seq_cst);
    if (miss_count)
        *miss_count = atomic_load_64(&cm->miss_count, memory_order_seq_cst);
}
