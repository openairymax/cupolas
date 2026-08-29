/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * Memory primitives (aligned alloc / lock / zero).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_MEM_H
#define cupolas_PLATFORM_MEM_H

#include "platform_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Memory Primitives
 * ============================================================================ */

/* Aligned Memory Allocation */
/**
 * @brief Allocate memory
 * @param[in] size Number of bytes to allocate
 * @return Pointer to allocated memory, NULL on failure
 * @note Thread-safe: Yes (heap operations are atomic)
 * @reentrant Yes
 */
void *cupolas_mem_alloc(size_t size);

/**
 * @brief Allocate aligned memory
 * @param[in] size Number of bytes to allocate
 * @param[in] alignment Alignment requirement (must be power of 2)
 * @return Pointer to allocated memory, NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void *cupolas_mem_alloc_aligned(size_t size, size_t alignment);

/**
 * @brief Free memory
 * @param[in] ptr Pointer to memory (NULL is safe)
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_mem_free(void *ptr);

/**
 * @brief Reallocate memory
 * @param[in] ptr Original pointer (NULL is safe for alloc)
 * @param[in] size New size in bytes
 * @return Pointer to reallocated memory, NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @post On failure, original pointer remains valid
 */
void *cupolas_mem_realloc(void *ptr, size_t size);

/* Secure Memory Operations */
/**
 * @brief Zero memory (secure erase)
 * @param[in] ptr Pointer to memory (must not be NULL)
 * @param[in] size Number of bytes to zero
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_mem_zero(void *ptr, size_t size);

/**
 * @brief Lock memory (prevent swapping)
 * @param[in] ptr Pointer to memory (must not be NULL)
 * @param[in] size Number of bytes to lock
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_mem_lock(void *ptr, size_t size);

/**
 * @brief Unlock memory
 * @param[in] ptr Pointer to memory (must not be NULL)
 * @param[in] size Number of bytes to unlock
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_mem_unlock(void *ptr, size_t size);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_MEM_H */
