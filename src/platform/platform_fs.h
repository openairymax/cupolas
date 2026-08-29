/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * File system primitives (cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_FS_H
#define cupolas_PLATFORM_FS_H

#include "platform_base.h"
#include "platform_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * File System Primitives
 * ============================================================================ */

/* File Path Maximum Length */
#if cupolas_PLATFORM_WINDOWS
#define cupolas_PATH_MAX 260
#define cupolas_PATH_SEP '\\'
#define cupolas_PATH_SEP_STR "\\"
#else
#define cupolas_PATH_MAX 4096
#define cupolas_PATH_SEP '/'
#define cupolas_PATH_SEP_STR "/"
#endif

/* File Attributes */
typedef struct cupolas_file_stat {
    uint64_t size;
    cupolas_timestamp_t mtime;
    bool is_dir;
    bool is_regular;
    bool exists;
} cupolas_file_stat_t;

/* File System Interface */
/**
 * @brief Get file statistics
 * @param[in] path File path (must not be NULL)
 * @param[out] stat Statistics output (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership stat: callee writes, caller owns
 */
int cupolas_file_stat(const char *path, cupolas_file_stat_t *stat);

/**
 * @brief Check if file exists
 * @param[in] path File path (must not be NULL)
 * @return true if exists, false otherwise
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_file_exists(const char *path);

/**
 * @brief Create directory
 * @param[in] path Directory path (must not be NULL)
 * @param[in] recursive Create parent directories if needed
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_file_mkdir(const char *path, bool recursive);

/**
 * @brief Remove file or empty directory
 * @param[in] path Path to remove (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_file_remove(const char *path);

/**
 * @brief Rename file
 * @param[in] old_path Old path (must not be NULL)
 * @param[in] new_path New path (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_file_rename(const char *old_path, const char *new_path);

/**
 * @brief Get absolute path
 * @param[in] path Input path (must not be NULL)
 * @param[out] buf Output buffer (must not be NULL)
 * @param[in] size Buffer size in bytes
 * @return Buffer on success, NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership buf: caller owns
 */
char *cupolas_file_abspath(const char *path, char *buf, size_t size);

/**
 * @brief Get directory name
 * @param[in] path Input path (must not be NULL)
 * @param[out] buf Output buffer (must not be NULL)
 * @param[in] size Buffer size in bytes
 * @return Buffer on success, NULL on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 * @ownership buf: caller owns
 */
char *cupolas_file_dirname(const char *path, char *buf, size_t size);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_FS_H */
