/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * Time / sleep primitives (cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_TIME_H
#define cupolas_PLATFORM_TIME_H

#include "platform_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Time Primitives
 * ============================================================================ */

/* Timestamp Structure */
typedef struct cupolas_timestamp {
    int64_t sec;
    int32_t nsec;
} cupolas_timestamp_t;

/* Time Interface */
/**
 * @brief Get current timestamp (wall clock)
 * @param[out] ts Timestamp output (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership ts: callee writes, caller owns
 */
int cupolas_time_now(cupolas_timestamp_t *ts);

/**
 * @brief Get monotonic timestamp
 * @param[out] ts Timestamp output (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership ts: callee writes, caller owns
 */
int cupolas_time_mono(cupolas_timestamp_t *ts);

/**
 * @brief Get current time in milliseconds
 * @return Current time in milliseconds since epoch
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
uint64_t cupolas_time_ms(void);

/**
 * @brief Sleep for milliseconds
 * @param[in] ms Milliseconds to sleep
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_sleep_ms(uint32_t ms);

/**
 * @brief Sleep for microseconds
 * @param[in] us Microseconds to sleep
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
void cupolas_sleep_us(uint32_t us);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_TIME_H */
