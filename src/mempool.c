// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file mempool.c
 * @brief P3.16: mempool minimum-guarantee allocator.
 *
 * Implementation notes:
 *   - Emergency reserve pool: preallocated fixed-size memory, usable only
 *     by HIGH/CRITICAL priorities
 *   - Object pool: fast fixed-size block allocation via a freelist
 *   - Tiered watermark: normal(50%) -> warn(75%) -> high(90%) -> critical
 *   - On OOM, CRITICAL priority is still guaranteed allocation (from the
 *     emergency reserve)
 *   - Low priorities are rejected at the HIGH watermark
 */

#include "mempool.h"
#include "airy_memory.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <pthread.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#define MEMPOOL_DEFAULT_RESERVE_SIZE (32UL * 1024 * 1024)

#define MEMPOOL_DEFAULT_BLOCK_SIZE 256

#define MEMPOOL_DEFAULT_BLOCK_COUNT 4096

#define MEMPOOL_MIN_ALLOC_SIZE 16

#define MEMPOOL_ALIGNMENT sizeof(void *)

#define MEMPOOL_ALIGN(s) (((s) + MEMPOOL_ALIGNMENT - 1) & ~(MEMPOOL_ALIGNMENT - 1))

typedef struct mempool_block {
    struct mempool_block *next;
    char data[];
} mempool_block_t;

typedef struct mempool_alloc {
    struct mempool_alloc *next;
    void *ptr;
    size_t size;
    airy_mempool_priority_t priority;
} mempool_alloc_t;

struct airy_mempool {

    void *reserve_base;
    size_t reserve_size;
    size_t reserve_used;
    size_t reserve_peak;

    size_t block_size;
    size_t block_count;
    mempool_block_t *free_list;
    size_t free_blocks;
    size_t total_blocks;

    mempool_alloc_t *alloc_list;

    size_t total_allocs;
    size_t total_frees;
    size_t oom_rejections;
    size_t emergency_allocs;

#ifdef __linux__
    pthread_mutex_t lock;
#elif defined(_WIN32)
    CRITICAL_SECTION lock;
#endif
};

static int mempool_mutex_init(airy_mempool_t *pool)
{
#ifdef __linux__
    return pthread_mutex_init(&pool->lock, NULL);
#elif defined(_WIN32)
    InitializeCriticalSection(&pool->lock);
    return 0;
#else
    (void)pool;
    return 0;
#endif
}

static void mempool_mutex_lock(airy_mempool_t *pool)
{
#ifdef __linux__
    pthread_mutex_lock(&pool->lock);
#elif defined(_WIN32)
    EnterCriticalSection(&pool->lock);
#else
    (void)pool;
#endif
}

static void mempool_mutex_unlock(airy_mempool_t *pool)
{
#ifdef __linux__
    pthread_mutex_unlock(&pool->lock);
#elif defined(_WIN32)
    LeaveCriticalSection(&pool->lock);
#else
    (void)pool;
#endif
}

static void mempool_mutex_destroy(airy_mempool_t *pool)
{
#ifdef __linux__
    pthread_mutex_destroy(&pool->lock);
#elif defined(_WIN32)
    DeleteCriticalSection(&pool->lock);
#else
    (void)pool;
#endif
}

/**
 * @brief Compute the current watermark level
 */
static airy_mempool_watermark_t mempool_calc_watermark(airy_mempool_t *pool)
{
    if (pool->reserve_size == 0)
        return MEMPOOL_WATERMARK_NORMAL;

    double usage = (double)pool->reserve_used / (double)pool->reserve_size;

    if (usage >= 0.90)
        return MEMPOOL_WATERMARK_CRITICAL;
    if (usage >= 0.75)
        return MEMPOOL_WATERMARK_HIGH;
    if (usage >= 0.50)
        return MEMPOOL_WATERMARK_WARN;
    return MEMPOOL_WATERMARK_NORMAL;
}

/**
 * @brief Allocate from the reserve pool
 */
static void *mempool_reserve_alloc(airy_mempool_t *pool, size_t size,
                                   airy_mempool_priority_t priority)
{
    airy_mempool_watermark_t wm = mempool_calc_watermark(pool);

    if (priority <= MEMPOOL_PRIORITY_LOW && wm >= MEMPOOL_WATERMARK_HIGH) {
        pool->oom_rejections++;
        return NULL;
    }

    if (priority <= MEMPOOL_PRIORITY_NORMAL && wm >= MEMPOOL_WATERMARK_CRITICAL) {
        pool->oom_rejections++;
        return NULL;
    }

    /* Check for enough space. Note: CRITICAL emergency allocations can push
     * reserve_used beyond reserve_size, so check reserve_used >= reserve_size
     * first to avoid subtracting underflow. */
    size_t remaining =
        (pool->reserve_used >= pool->reserve_size) ? 0 : (pool->reserve_size - pool->reserve_used);
    if (size > remaining) {

        if (priority == MEMPOOL_PRIORITY_CRITICAL) {

            void *ptr = malloc(size);
            if (ptr) {
                pool->emergency_allocs++;
                pool->reserve_used += size;
                if (pool->reserve_used > pool->reserve_peak) {
                    pool->reserve_peak = pool->reserve_used;
                }
            }
            return ptr;
        }
        pool->oom_rejections++;
        return NULL;
    }

    void *ptr = (char *)pool->reserve_base + pool->reserve_used;
    pool->reserve_used += size;
    if (pool->reserve_used > pool->reserve_peak) {
        pool->reserve_peak = pool->reserve_used;
    }

    return ptr;
}

/**
 * @brief Allocate from the object pool
 */
static void *mempool_block_alloc(airy_mempool_t *pool)
{
    if (!pool->free_list)
        return NULL;

    mempool_block_t *block = pool->free_list;
    pool->free_list = block->next;
    pool->free_blocks--;

    return block->data;
}

/**
 * @brief Return an object-pool block
 */
static void mempool_block_free(airy_mempool_t *pool, void *ptr)
{
    if (!ptr)
        return;

    mempool_block_t *block = (mempool_block_t *)((char *)ptr - sizeof(mempool_block_t));

    block->next = pool->free_list;
    pool->free_list = block;
    pool->free_blocks++;
}

/**
 * @brief Check whether a pointer comes from the object pool
 */
static bool mempool_is_block_ptr(airy_mempool_t *pool, void *ptr)
{

    if (!pool->reserve_base)
        return false;

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t base = (uintptr_t)pool->reserve_base;
    uintptr_t end = base + pool->reserve_size;

    return (addr < base || addr >= end);
}

/**
 * @brief Initialize the object pool
 */
static int mempool_init_blocks(airy_mempool_t *pool)
{
    size_t total_alloc_size = (sizeof(mempool_block_t) + pool->block_size) * pool->block_count;

    char *raw = (char *)calloc(1, total_alloc_size);
    if (!raw)
        return AIRY_ERR_OUT_OF_MEMORY;

    pool->free_list = NULL;
    pool->free_blocks = 0;
    pool->total_blocks = pool->block_count;

    for (size_t i = 0; i < pool->block_count; i++) {
        mempool_block_t *block =
            (mempool_block_t *)(raw + i * (sizeof(mempool_block_t) + pool->block_size));
        block->next = pool->free_list;
        pool->free_list = block;
        pool->free_blocks++;
    }

    return 0;
}

airy_mempool_t *airy_mempool_create(size_t reserve_size, size_t block_size, size_t block_count)
{
    airy_mempool_t *pool = (airy_mempool_t *)AIRY_CALLOC(1, sizeof(*pool));
    if (!pool) {
        LOG_ERROR("Mempool: OOM allocating pool struct");
        return NULL;
    }

    pool->reserve_size = reserve_size > 0 ? reserve_size : MEMPOOL_DEFAULT_RESERVE_SIZE;
    pool->block_size = MEMPOOL_ALIGN(block_size > 0 ? block_size : MEMPOOL_DEFAULT_BLOCK_SIZE);
    pool->block_count = block_count > 0 ? block_count : MEMPOOL_DEFAULT_BLOCK_COUNT;

    LOG_INFO("Mempool: creating (reserve=%zuMB, block_size=%zu, block_count=%zu)",
             pool->reserve_size / (1024 * 1024), pool->block_size, pool->block_count);

    pool->reserve_base = AIRY_CALLOC(1, pool->reserve_size);
    if (!pool->reserve_base) {
        LOG_ERROR("Mempool: OOM allocating reserve pool (%zuMB)",
                  pool->reserve_size / (1024 * 1024));
        AIRY_FREE(pool);
        return NULL;
    }

    LOG_INFO("Mempool: reserve pool allocated at %p (%zuMB)", pool->reserve_base,
             pool->reserve_size / (1024 * 1024));

    if (mempool_init_blocks(pool) != 0) {
        LOG_ERROR("Mempool: failed to init object pool blocks");
        AIRY_FREE(pool->reserve_base);
        AIRY_FREE(pool);
        return NULL;
    }

    LOG_INFO("Mempool: object pool initialized (%zu blocks of %zu bytes)", pool->block_count,
             pool->block_size);

    if (mempool_mutex_init(pool) != 0) {
        LOG_ERROR("Mempool: mutex init failed");
        AIRY_FREE(pool->reserve_base);
        AIRY_FREE(pool);
        return NULL;
    }

    LOG_INFO("Mempool: created successfully");
    return pool;
}

void airy_mempool_destroy(airy_mempool_t *pool)
{
    if (!pool)
        return;

    LOG_INFO("Mempool: destroying (total_allocs=%zu, total_frees=%zu, "
             "oom_rejections=%zu, emergency_allocs=%zu, "
             "reserve_used=%zu/%zu, blocks_used=%zu/%zu)",
             pool->total_allocs, pool->total_frees, pool->oom_rejections, pool->emergency_allocs,
             pool->reserve_used, pool->reserve_size, pool->total_blocks - pool->free_blocks,
             pool->total_blocks);

    mempool_mutex_lock(pool);

    mempool_alloc_t *alloc = pool->alloc_list;
    size_t alloc_records = 0;
    while (alloc) {
        mempool_alloc_t *next = alloc->next;
        AIRY_FREE(alloc);
        alloc = next;
        alloc_records++;
    }

    if (pool->reserve_base) {
        AIRY_FREE(pool->reserve_base);
        pool->reserve_base = NULL;
    }

    mempool_mutex_unlock(pool);
    mempool_mutex_destroy(pool);

    AIRY_FREE(pool);

    LOG_INFO("Mempool: destroyed (%zu alloc records freed)", alloc_records);
}

void *airy_mempool_alloc(airy_mempool_t *pool, size_t size, airy_mempool_priority_t priority)
{
    if (!pool || size == 0) {
        LOG_DEBUG("Mempool: alloc called with NULL pool or size=0");
        return NULL;
    }

    size_t aligned_size = MEMPOOL_ALIGN(size);
    if (aligned_size < MEMPOOL_MIN_ALLOC_SIZE) {
        aligned_size = MEMPOOL_MIN_ALLOC_SIZE;
    }

    mempool_mutex_lock(pool);

    void *ptr = NULL;
    airy_mempool_watermark_t wm = mempool_calc_watermark(pool);

    if (aligned_size == pool->block_size && pool->free_blocks > 0) {
        ptr = mempool_block_alloc(pool);
        if (ptr) {
            pool->total_allocs++;
            LOG_DEBUG("Mempool: alloc from object pool (size=%zu, "
                      "priority=%d, free_blocks=%zu)",
                      aligned_size, priority, pool->free_blocks);
            mempool_mutex_unlock(pool);
            return ptr;
        }
    }

    ptr = mempool_reserve_alloc(pool, aligned_size, priority);
    if (ptr) {
        pool->total_allocs++;

        mempool_alloc_t *record = (mempool_alloc_t *)AIRY_MALLOC(sizeof(*record));
        if (record) {
            record->ptr = ptr;
            record->size = aligned_size;
            record->priority = priority;
            record->next = pool->alloc_list;
            pool->alloc_list = record;
        }

        LOG_DEBUG("Mempool: alloc from reserve pool (size=%zu, "
                  "priority=%d, watermark=%d, reserve_used=%zu/%zu)",
                  aligned_size, priority, wm, pool->reserve_used, pool->reserve_size);

        if (priority == MEMPOOL_PRIORITY_CRITICAL) {
            LOG_WARN("Mempool: emergency allocation (size=%zu, "
                     "watermark=%d, reserve_used=%zu/%zu)",
                     aligned_size, wm, pool->reserve_used, pool->reserve_size);
        }
    } else {
        LOG_WARN("Mempool: alloc rejected (size=%zu, priority=%d, "
                 "watermark=%d, reserve_used=%zu/%zu, oom_rejections=%zu)",
                 aligned_size, priority, wm, pool->reserve_used, pool->reserve_size,
                 pool->oom_rejections + 1);
    }

    mempool_mutex_unlock(pool);
    return ptr;
}

void airy_mempool_free(airy_mempool_t *pool, void *ptr)
{
    if (!pool || !ptr)
        return;

    mempool_mutex_lock(pool);

    if (mempool_is_block_ptr(pool, ptr)) {
        mempool_block_free(pool, ptr);
        pool->total_frees++;
        LOG_DEBUG("Mempool: free to object pool (free_blocks=%zu)", pool->free_blocks);
        mempool_mutex_unlock(pool);
        return;
    }

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t base = (uintptr_t)pool->reserve_base;
    uintptr_t end = base + pool->reserve_size;

    if (addr >= base && addr < end) {

        pool->total_frees++;

        mempool_alloc_t **prev = &pool->alloc_list;
        while (*prev) {
            if ((*prev)->ptr == ptr) {
                mempool_alloc_t *to_free = *prev;
                *prev = to_free->next;
                AIRY_FREE(to_free);
                break;
            }
            prev = &(*prev)->next;
        }

        LOG_DEBUG("Mempool: free from reserve pool (reserve_used=%zu)", pool->reserve_used);
    } else {
        LOG_WARN("Mempool: free called with ptr not owned by pool %p", ptr);
    }

    mempool_mutex_unlock(pool);
}

int airy_mempool_get_stats(airy_mempool_t *pool, airy_mempool_stats_t *stats)
{
    if (!pool || !stats)
        return AIRY_ERR_INVALID_PARAM;

    mempool_mutex_lock(pool);

    stats->total_reserved = pool->reserve_size;
    stats->total_allocated = pool->reserve_used;
    stats->peak_allocated = pool->reserve_peak;
    stats->available_reserved =
        pool->reserve_size > pool->reserve_used ? pool->reserve_size - pool->reserve_used : 0;
    stats->object_pool_total = pool->total_blocks;
    stats->object_pool_used = pool->total_blocks - pool->free_blocks;
    stats->total_allocs = pool->total_allocs;
    stats->total_frees = pool->total_frees;
    stats->oom_rejections = pool->oom_rejections;
    stats->emergency_allocs = pool->emergency_allocs;
    stats->watermark = mempool_calc_watermark(pool);

    mempool_mutex_unlock(pool);
    return 0;
}

airy_mempool_watermark_t airy_mempool_get_watermark(airy_mempool_t *pool)
{
    if (!pool)
        return MEMPOOL_WATERMARK_NORMAL;

    mempool_mutex_lock(pool);
    airy_mempool_watermark_t wm = mempool_calc_watermark(pool);
    mempool_mutex_unlock(pool);
    return wm;
}

size_t airy_mempool_shrink(airy_mempool_t *pool)
{
    if (!pool)
        return 0;

    (void)pool;
    return 0;
}

bool airy_mempool_validate(airy_mempool_t *pool)
{
    if (!pool)
        return false;

    mempool_mutex_lock(pool);

    if (pool->reserve_base == NULL) {
        mempool_mutex_unlock(pool);
        return false;
    }

    size_t visited = 0;
    mempool_block_t *block = pool->free_list;
    while (block && visited < pool->total_blocks * 2) {
        visited++;
        block = block->next;
    }

    if (visited != pool->free_blocks) {
        mempool_mutex_unlock(pool);
        return false;
    }

    if (pool->reserve_used > pool->reserve_size) {
        mempool_mutex_unlock(pool);
        return false;
    }

    mempool_mutex_unlock(pool);
    return true;
}
