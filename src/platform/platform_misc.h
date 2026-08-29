/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * String utilities (case-insensitive compare).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_MISC_H
#define cupolas_PLATFORM_MISC_H

#include "platform_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * String Utilities
 * ============================================================================ */

/**
 * @brief Duplicate string
 * @param[in] str String to duplicate (must not be NULL)
 * @return Duplicated string (caller owns, must free), NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership Returned string: caller owns, must call cupolas_mem_free
 */
char *cupolas_strdup(const char *str);

/**
 * @brief Duplicate string with length limit
 * @param[in] str String to duplicate (must not be NULL)
 * @param[in] n Maximum length
 * @return Duplicated string (caller owns, must free), NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership Returned string: caller owns, must call cupolas_mem_free
 */
char *cupolas_strndup(const char *str, size_t n);

/**
 * @brief Case-insensitive string comparison
 * @param[in] s1 First string (must not be NULL)
 * @param[in] s2 Second string (must not be NULL)
 * @return Comparison result (like strcmp)
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_strcasecmp(const char *s1, const char *s2);

/**
 * @brief Case-insensitive string comparison with length limit
 * @param[in] s1 First string (must not be NULL)
 * @param[in] s2 Second string (must not be NULL)
 * @param[in] n Maximum length to compare
 * @return Comparison result (like strncmp)
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_strncasecmp(const char *s1, const char *s2, size_t n);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_MISC_H */
