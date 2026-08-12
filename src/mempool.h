/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file mempool.h
 * @brief P3.16: mempool minimum-guarantee allocator.
 *
 * Guarantees memory allocation for critical paths (e.g. IPC messages) under
 * OOM conditions. Key features:
 *   - Emergency reserve pool (default 32MB)
 *   - Object pool (fast fixed-size object allocation)
 *   - Minimum-guarantee allocation (critical paths served first on OOM)
 *   - Tiered watermarks (normal/warn/high/critical)
 *
 * Typical usage:
 *   airy_mempool_t *pool = airy_mempool_create(32 * 1024 * 1024, 256, 1024);
 *   void *buf = airy_mempool_alloc(pool, 512, MEMPOOL_PRIORITY_CRITICAL);
 *   // ... use buf ...
 *   airy_mempool_free(pool, buf);
 *   airy_mempool_destroy(pool);
 */

#ifndef CUPOLAS_MEMPOOL_H
#define CUPOLAS_MEMPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMPOOL_DEFAULT_RESERVE_MB 32

#define MEMPOOL_DEFAULT_BLOCK_SIZE 256

#define MEMPOOL_DEFAULT_BLOCK_COUNT 4096

typedef struct airy_mempool airy_mempool_t;

typedef enum {
    MEMPOOL_PRIORITY_LOW = 0,
    MEMPOOL_PRIORITY_NORMAL = 1,
    MEMPOOL_PRIORITY_HIGH = 2,
    MEMPOOL_PRIORITY_CRITICAL = 3,
} airy_mempool_priority_t;

typedef enum {
    MEMPOOL_WATERMARK_NORMAL = 0,
    MEMPOOL_WATERMARK_WARN = 1,
    MEMPOOL_WATERMARK_HIGH = 2,
    MEMPOOL_WATERMARK_CRITICAL = 3,
} airy_mempool_watermark_t;

typedef struct {
    size_t total_reserved;
    size_t total_allocated;
    size_t peak_allocated;
    size_t available_reserved;
    size_t object_pool_total;
    size_t object_pool_used;
    size_t total_allocs;
    size_t total_frees;
    size_t oom_rejections;
    size_t emergency_allocs;
    airy_mempool_watermark_t watermark;
} airy_mempool_stats_t;

/**
 * @brief Create a memory pool
 *
 * @param reserve_size Emergency reserve size in bytes, 0 for the default 32MB
 * @param block_size Object-pool block size in bytes, 0 for the default 256B
 * @param block_count Object-pool block count, 0 for the default 4096
 * @return Memory pool handle, NULL on failure
 *
 * @ownership Returned handle is caller-managed; release with
 *            airy_mempool_destroy()
 * @threadsafe Yes
 */
airy_mempool_t *airy_mempool_create(size_t reserve_size, size_t block_size, size_t block_count);

/**
 * @brief Destroy a memory pool
 *
 * Releases all reserve memory and the object pool.
 *
 * @param pool Memory pool handle
 *
 * @ownership pool: TRANSFER
 * @threadsafe No
 */
void airy_mempool_destroy(airy_mempool_t *pool);

/**
 * @brief Allocate memory from the pool
 *
 * Allocation strategy:
 *   - Size == block_size -> served from the object pool first
 *   - Other sizes -> allocated from the reserve pool
 *   - CRITICAL priority -> still guaranteed on OOM (from the emergency
 *     reserve)
 *   - Watermark warnings -> low-priority allocations may be rejected
 *
 * @param pool Memory pool handle
 * @param size Allocation size in bytes
 * @param priority Allocation priority
 * @return Memory pointer, NULL on failure
 *
 * @ownership Returned memory is caller-managed; return it with
 *            airy_mempool_free()
 * @threadsafe Yes
 */
void *airy_mempool_alloc(airy_mempool_t *pool, size_t size, airy_mempool_priority_t priority);

/**
 * @brief Return memory to the pool
 *
 * @param pool Memory pool handle
 * @param ptr Memory pointer (NULL is a no-op)
 *
 * @ownership ptr: TRANSFER
 * @threadsafe Yes
 */
void airy_mempool_free(airy_mempool_t *pool, void *ptr);

/**
 * @brief Get memory pool statistics
 *
 * @param pool Memory pool handle
 * @param stats Statistics output
 * @return 0 on success, non-zero on failure
 */
int airy_mempool_get_stats(airy_mempool_t *pool, airy_mempool_stats_t *stats);

/**
 * @brief Get the current watermark
 *
 * @param pool Memory pool handle
 * @return Current watermark level
 */
airy_mempool_watermark_t airy_mempool_get_watermark(airy_mempool_t *pool);

/**
 * @brief Shrink the pool: release idle object-pool blocks
 *
 * @param pool Memory pool handle
 * @return Number of blocks released
 */
size_t airy_mempool_shrink(airy_mempool_t *pool);

/**
 * @brief Validate internal pool consistency
 *
 * @param pool Memory pool handle
 * @return true if consistent, false if corrupted
 */
bool airy_mempool_validate(airy_mempool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_MEMPOOL_H */
