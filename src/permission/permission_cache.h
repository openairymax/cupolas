/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * permission_cache.h - Permission Cache Interface
 */

#ifndef CUPOLAS_PERMISSION_CACHE_H
#define CUPOLAS_PERMISSION_CACHE_H

#include "platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Permission cache handle (opaque)
 *
 * Backed by the cache_common LRU atom. The concrete layout is private to
 * permission_cache.c, so the storage atom can be replaced without touching
 * any consumer.
 */
typedef struct cache_manager cache_manager_t;

/**
 * @brief Create permission cache
 * @param[in] capacity Maximum number of cache entries
 * @param[in] ttl_ms Time-to-live in milliseconds (0 = permanent/no expiration)
 * @return Cache manager handle, NULL on failure
 * @note Thread-safe: Safe to call from multiple threads
 * @reentrant Yes
 * @ownership Returns owned pointer: caller must call cache_manager_destroy()
 */
cache_manager_t *cache_manager_create(size_t capacity, uint32_t ttl_ms);

/**
 * @brief Destroy cache manager and free all resources
 * @param[in] cm Cache manager handle (may be NULL)
 * @note Thread-safe: Safe to call from multiple threads (but not concurrently with other
 * operations)
 * @reentrant No
 * @ownership cm: transferred to this function, will be freed
 */
void cache_manager_destroy(cache_manager_t *cm);

/**
 * @brief Get cached permission result
 * @param[in] cm Cache manager handle
 * @param[in] agent_id Agent identifier
 * @param[in] action Action being performed
 * @param[in] resource Resource being accessed
 * @param[in] context Context information
 * @return 1=allowed, 0=denied, -1=cache miss or error
 * @note Thread-safe: Safe to call from multiple threads concurrently
 * @reentrant Yes
 * @ownership All parameters: caller retains ownership, may be NULL
 */
int cache_manager_get(cache_manager_t *cm, const char *agent_id, const char *action,
                      const char *resource, const char *context);

/**
 * @brief Store permission result in cache
 * @param[in] cm Cache manager handle
 * @param[in] agent_id Agent identifier
 * @param[in] action Action being performed
 * @param[in] resource Resource being accessed
 * @param[in] context Context information
 * @param[in] result Permission result (1=allow, 0=deny); other values are not cached
 * @note Thread-safe: Safe to call from multiple threads concurrently
 * @reentrant Yes
 * @ownership All string parameters: caller retains ownership
 */
void cache_manager_put(cache_manager_t *cm, const char *agent_id, const char *action,
                       const char *resource, const char *context, int result);

/**
 * @brief Clear all cache entries
 * @param[in] cm Cache manager handle
 * @note Thread-safe: Safe to call from multiple threads (but not concurrently with other
 * operations)
 * @reentrant No
 */
void cache_manager_clear(cache_manager_t *cm);

/**
 * @brief Get cache statistics
 * @param[in] cm Cache manager handle
 * @param[out] hit_count Cache hit counter (may be NULL)
 * @param[out] miss_count Cache miss counter (may be NULL)
 * @note Thread-safe: Safe to call from multiple threads concurrently
 * @reentrant Yes
 */
void cache_manager_stats(cache_manager_t *cm, uint64_t *hit_count, uint64_t *miss_count);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_PERMISSION_CACHE_H */
