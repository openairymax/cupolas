// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * permission_cache.c - Permission Cache Implementation
 */

/**
 * @file permission_cache.c
 * @brief Permission result cache: key/TTL policy over the shared cache atom.
 * @author SPHARX Ltd. - Airymax Team
 *
 * Only the *policy* lives here: flattening the (agent, action, resource,
 * context) tuple into a lookup key, encoding the tri-state decision
 * (-1 miss / 0 deny / 1 allow) into a cache value, and the millisecond to
 * second TTL conversion. The bounded LRU store, locking and eviction are the
 * cache_common atom (commons/utils/cache).
 */

#include "permission_cache.h"

#include "airy_memory.h"
#include "cache_common.h"

#include <string.h>

#define CACHE_TTL_MS_TO_SEC(ms) (((ms) + 999) / 1000)
#define CACHE_CAP_DEF 1024
#define CACHE_KEY_PARTS 4

struct cache_manager {
    cache_t inner;
};

static char *perm_key_make(const char *agent_id, const char *action, const char *resource,
                           const char *context)
{
    const char *parts[CACHE_KEY_PARTS] = {agent_id, action, resource, context};

    size_t len = 1 + (CACHE_KEY_PARTS - 1);
    for (int i = 0; i < CACHE_KEY_PARTS; i++) {
        if (parts[i])
            len += strlen(parts[i]);
    }

    char *key = (char *)AIRY_CALLOC(1, len);
    if (!key)
        return NULL;

    char *p = key;
    for (int i = 0; i < CACHE_KEY_PARTS; i++) {
        if (parts[i]) {
            size_t n = strlen(parts[i]);
            AIRY_MEMCPY(p, parts[i], n);
            p += n;
        }
        if (i < CACHE_KEY_PARTS - 1)
            *p++ = ':';
    }
    *p = '\0';

    return key;
}

cache_manager_t *cache_manager_create(size_t capacity, uint32_t ttl_ms)
{
    cache_manager_t *cm = (cache_manager_t *)AIRY_CALLOC(1, sizeof(cache_manager_t));
    if (!cm)
        return NULL;

    size_t cap = capacity > 0 ? capacity : CACHE_CAP_DEF;
    cm->inner = cache_create_string_cache(cap, (int)CACHE_TTL_MS_TO_SEC(ttl_ms));
    if (!cm->inner) {
        AIRY_FREE(cm);
        return NULL;
    }

    return cm;
}

void cache_manager_destroy(cache_manager_t *cm)
{
    if (!cm)
        return;

    cache_destroy(cm->inner);
    AIRY_FREE(cm);
}

int cache_manager_get(cache_manager_t *cm, const char *agent_id, const char *action,
                      const char *resource, const char *context)
{
    if (!cm)
        return -1;

    char *key = perm_key_make(agent_id, action, resource, context);
    if (!key)
        return -1;

    char *value = NULL;
    int hit = cache_get_string(cm->inner, key, &value);
    AIRY_FREE(key);

    if (hit != 1 || !value)
        return -1;

    int result = value[0] == '1' ? 1 : 0;
    AIRY_FREE(value);
    return result;
}

void cache_manager_put(cache_manager_t *cm, const char *agent_id, const char *action,
                       const char *resource, const char *context, int result)
{
    if (!cm || (result != 0 && result != 1))
        return;

    char *key = perm_key_make(agent_id, action, resource, context);
    if (!key)
        return;

    cache_put_string(cm->inner, key, result ? "1" : "0");
    AIRY_FREE(key);
}

void cache_manager_clear(cache_manager_t *cm)
{
    if (cm)
        cache_clear(cm->inner);
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

    cache_stats_t stats;
    cache_get_stats(cm->inner, &stats);

    if (hit_count)
        *hit_count = (uint64_t)stats.hits;
    if (miss_count)
        *miss_count = (uint64_t)stats.misses;
}
