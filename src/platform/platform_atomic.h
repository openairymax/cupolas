/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * Atomic operations (32/64/pointer, cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_ATOMIC_H
#define cupolas_PLATFORM_ATOMIC_H

#include "platform_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Atomic Operations
 * ============================================================================ */

typedef volatile int32_t cupolas_atomic32_t;
typedef volatile int64_t cupolas_atomic64_t;
typedef volatile void *cupolas_atomic_ptr_t;

/**
 * @brief Load 32-bit atomic value
 * @param[in] ptr Atomic variable (must not be NULL)
 * @return Value at ptr
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int32_t cupolas_atomic_load32(cupolas_atomic32_t *ptr);

/**
 * @brief Store 32-bit atomic value
 * @param[out] ptr Atomic variable (must not be NULL)
 * @param[in] val Value to store
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_atomic_store32(cupolas_atomic32_t *ptr, int32_t val);

/**
 * @brief Add to 32-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] delta Value to add
 * @return New value after addition
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int32_t cupolas_atomic_add32(cupolas_atomic32_t *ptr, int32_t delta);

/**
 * @brief Subtract from 32-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] delta Value to subtract
 * @return New value after subtraction
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int32_t cupolas_atomic_sub32(cupolas_atomic32_t *ptr, int32_t delta);

/**
 * @brief Increment 32-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @return Value after increment
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int32_t cupolas_atomic_inc32(cupolas_atomic32_t *ptr);

/**
 * @brief Decrement 32-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @return Value after decrement
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int32_t cupolas_atomic_dec32(cupolas_atomic32_t *ptr);

/**
 * @brief Compare and swap 32-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] expected Expected current value
 * @param[in] desired Desired new value
 * @return true if swapped, false if current value != expected
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
bool cupolas_atomic_cas32(cupolas_atomic32_t *ptr, int32_t expected, int32_t desired);

/**
 * @brief Load 64-bit atomic value
 * @param[in] ptr Atomic variable (must not be NULL)
 * @return Value at ptr
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int64_t cupolas_atomic_load64(cupolas_atomic64_t *ptr);

/**
 * @brief Store 64-bit atomic value
 * @param[out] ptr Atomic variable (must not be NULL)
 * @param[in] val Value to store
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_atomic_store64(cupolas_atomic64_t *ptr, int64_t val);

/**
 * @brief Add to 64-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] delta Value to add
 * @return New value after addition
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int64_t cupolas_atomic_add64(cupolas_atomic64_t *ptr, int64_t delta);

/**
 * @brief Subtract from 64-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] delta Value to subtract
 * @return New value after subtraction
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int64_t cupolas_atomic_sub64(cupolas_atomic64_t *ptr, int64_t delta);

/**
 * @brief Compare and swap 64-bit atomic value
 * @param[inout] ptr Atomic variable (must not be NULL)
 * @param[in] expected Expected current value
 * @param[in] desired Desired new value
 * @return true if swapped, false if current value != expected
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
bool cupolas_atomic_cas64(cupolas_atomic64_t *ptr, int64_t expected, int64_t desired);

/**
 * @brief Load pointer atomic value
 * @param[in] ptr Atomic pointer variable (must not be NULL)
 * @return Value at ptr
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void *cupolas_atomic_load_ptr(cupolas_atomic_ptr_t *ptr);

/**
 * @brief Store pointer atomic value
 * @param[out] ptr Atomic pointer variable (must not be NULL)
 * @param[in] val Value to store
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_atomic_store_ptr(cupolas_atomic_ptr_t *ptr, void *val);

/**
 * @brief Compare and swap pointer atomic value
 * @param[inout] ptr Atomic pointer variable (must not be NULL)
 * @param[in] expected Expected current value
 * @param[in] desired Desired new value
 * @return true if swapped, false if current value != expected
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
bool cupolas_atomic_cas_ptr(cupolas_atomic_ptr_t *ptr, void *expected, void *desired);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_ATOMIC_H */
