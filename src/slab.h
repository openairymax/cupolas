/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file slab.h
 * @brief P3.15: slab allocator -- per-CPU freelist, global partial chain,
 *        and ctor/dtor callbacks.
 *
 * Slab allocator for high-frequency allocation/free of fixed-size objects.
 * Core advantages:
 *   - O(1) alloc/free (per-CPU freelist)
 *   - Zero fragmentation (fixed-size objects)
 *   - Ctor/dtor callbacks (C++-style RAII support)
 *   - Global partial chain (cross-CPU load balancing)
 *
 * Typical usage:
 *   airy_slab_t *slab = airy_slab_create(sizeof(my_struct), 64, NULL, NULL);
 *   my_struct *obj = (my_struct *)airy_slab_alloc(slab);
 *   // ... use obj ...
 *   airy_slab_free(slab, obj);
 *   airy_slab_destroy(slab);
 */

#ifndef CUPOLAS_SLAB_H
#define CUPOLAS_SLAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct airy_slab airy_slab_t;

typedef void (*airy_slab_ctor_t)(void *obj, void *user_data);

typedef void (*airy_slab_dtor_t)(void *obj, void *user_data);

typedef struct {
    size_t obj_size;
    size_t objs_per_slab;
    size_t total_slabs;
    size_t full_slabs;
    size_t partial_slabs;
    size_t empty_slabs;
    size_t total_allocs;
    size_t total_frees;
    size_t active_objects;
    size_t cpu_steals;
} airy_slab_stats_t;

/**
 * @brief Create a slab allocator
 *
 * @param obj_size      Object size in bytes, auto-aligned to sizeof(void*)
 * @param objs_per_slab Objects per slab page, 0 for the default (derived
 *                      from obj_size)
 * @param ctor          Constructor callback (may be NULL)
 * @param dtor          Destructor callback (may be NULL)
 * @param user_data     User data passed to the ctor/dtor callbacks
 * @return Slab handle, NULL on failure
 *
 * @ownership Returned handle is caller-managed; release with
 *            airy_slab_destroy()
 * @threadsafe Yes (per-CPU freelist + global lock)
 */
airy_slab_t *airy_slab_create(size_t obj_size, size_t objs_per_slab, airy_slab_ctor_t ctor,
                              airy_slab_dtor_t dtor, void *user_data);

/**
 * @brief Destroy a slab allocator
 *
 * Releases all slab pages and the slab structure itself.
 * Note: does not call the destructor on allocated objects (the caller must
 * ensure all objects are freed first).
 *
 * @param slab Slab handle
 *
 * @ownership slab: TRANSFER
 * @threadsafe No (the caller must ensure no concurrent access)
 */
void airy_slab_destroy(airy_slab_t *slab);

/**
 * @brief Allocate an object from the slab
 *
 * Served from the current CPU's freelist first, then from the global
 * partial chain. The constructor callback is invoked automatically after
 * allocation (if set).
 *
 * @param slab Slab handle
 * @return Object pointer, NULL on failure
 *
 * @ownership Returned object is caller-managed; return it with
 *            airy_slab_free()
 * @threadsafe Yes
 */
void *airy_slab_alloc(airy_slab_t *slab);

/**
 * @brief Return an object to the slab
 *
 * The destructor callback is invoked automatically before freeing (if set).
 * The object goes back to the current CPU's freelist; if that freelist is
 * full it is returned to the global partial chain.
 *
 * @param slab Slab handle
 * @param obj  Object pointer (NULL is a no-op)
 *
 * @ownership obj: TRANSFER
 * @threadsafe Yes
 */
void airy_slab_free(airy_slab_t *slab, void *obj);

/**
 * @brief Get slab statistics
 *
 * @param slab  Slab handle
 * @param stats Statistics output
 * @return 0 on success, non-zero on failure
 */
int airy_slab_get_stats(airy_slab_t *slab, airy_slab_stats_t *stats);

/**
 * @brief Shrink the slab: release all empty slab pages
 *
 * @param slab Slab handle
 * @return Number of slab pages released
 */
size_t airy_slab_shrink(airy_slab_t *slab);

/**
 * @brief Validate internal slab consistency
 *
 * @param slab Slab handle
 * @return true if consistent, false if corrupted
 */
bool airy_slab_validate(airy_slab_t *slab);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_SLAB_H */
