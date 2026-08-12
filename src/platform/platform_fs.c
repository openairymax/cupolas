// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform_fs.c - Cross-Platform Abstraction Layer (File System)
 */

/**
 * @file platform_fs.c
 * @brief cupolas 平台抽象层 - 文件系统域
 *
 * 本文件实现文件状态查询、存在性/目录/删除/重命名/绝对路径/目录名等操作。
 */

#include "platform.h"
#include "platform_internal.h"

#include "atomic_compat.h"
#include "airy_memory.h"
#include "string_compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include "airy_mman.h"
#endif

#if cupolas_PLATFORM_WINDOWS
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#define getcwd _getcwd
#define rmdir _rmdir
#define unlink _unlink
#define access _access /* flawfinder: ignore */
#define F_OK 0
#define W_OK 2
#define R_OK 4
#else
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#include "error.h"

/* ============================================================================
 * File System Implementation
 * ============================================================================ */

int cupolas_file_stat(const char *path, cupolas_file_stat_t *file_stat)
{
    if (!path || !file_stat)
        return cupolas_ERROR_INVALID_ARG;
    __builtin_memset(file_stat, 0, sizeof(*file_stat));

#if cupolas_PLATFORM_WINDOWS
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) {
            file_stat->exists = false;
            return 0;
        }
        return cupolas_ERROR_IO;
    }

    file_stat->exists = true;
    file_stat->is_dir = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    file_stat->is_regular = !file_stat->is_dir;
    file_stat->size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

    ULARGE_INTEGER uli;
    uli.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    uli.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    uint64_t ns100 = uli.QuadPart;
    file_stat->mtime.sec = (int64_t)(ns100 / 10000000ULL - 11644473600ULL);
    file_stat->mtime.nsec = (int32_t)((ns100 % 10000000ULL) * 100);
    return 0;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            file_stat->exists = false;
            return 0;
        }
        return cupolas_ERROR_IO;
    }

    file_stat->exists = true;
    file_stat->is_dir = S_ISDIR(st.st_mode) != 0;
    file_stat->is_regular = S_ISREG(st.st_mode) != 0;
    file_stat->size = (uint64_t)st.st_size;
    file_stat->mtime.sec = st.st_mtime;
    file_stat->mtime.nsec = 0;
    return 0;
#endif
}

int cupolas_file_exists(const char *path)
{
    if (!path)
        return 0;
#if cupolas_PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
#else
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
#endif
}

int cupolas_file_mkdir(const char *path, bool recursive)
{
    if (!path)
        return cupolas_ERROR_INVALID_ARG;
#if cupolas_PLATFORM_WINDOWS
    if (recursive) {
        char tmp[cupolas_PATH_MAX];
        AIRY_STRNCPY_TERM(tmp, path, sizeof(tmp));
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '\\' || *p == '/') {
                *p = '\0';
                CreateDirectoryA(tmp, NULL);
                *p = '\\';
            }
        }
    }
    return CreateDirectoryA(path, NULL) ? 0 : cupolas_ERROR_IO;
#else
    if (recursive) {
        char tmp[cupolas_PATH_MAX];
        AIRY_STRNCPY_TERM(tmp, path, sizeof(tmp));
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
        }
    }
    return mkdir(path, 0755) == 0 ? 0 : cupolas_ERROR_IO;
#endif
}

int cupolas_file_remove(const char *path)
{
    if (!path)
        return cupolas_ERROR_INVALID_ARG;
#if cupolas_PLATFORM_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return cupolas_ERROR_NOT_FOUND;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        return RemoveDirectoryA(path) ? 0 : cupolas_ERROR_IO;
    return DeleteFileA(path) ? 0 : cupolas_ERROR_IO;
#else
    return unlink(path) == 0 ? 0 : cupolas_ERROR_IO;
#endif
}

int cupolas_file_rename(const char *old_path, const char *new_path)
{
    if (!old_path || !new_path)
        return cupolas_ERROR_INVALID_ARG;
#if cupolas_PLATFORM_WINDOWS
    return MoveFileExA(old_path, new_path, MOVEFILE_REPLACE_EXISTING) ? 0 : cupolas_ERROR_IO;
#else
    return rename(old_path, new_path) == 0 ? 0 : cupolas_ERROR_IO;
#endif
}

char *cupolas_file_abspath(const char *path, char *buf, size_t size)
{
    if (!path || !buf || size == 0)
        return NULL;
#if cupolas_PLATFORM_WINDOWS
    DWORD ret = GetFullPathNameA(path, (DWORD)size, buf, NULL);
    return (ret > 0 && ret < size) ? buf : NULL;
#else
    if (realpath(path, buf))
        return buf;
    if (strlen(path) < size) {
        AIRY_STRNCPY_TERM(buf, path, size);
        return buf;
    }
    return NULL;
#endif
}

char *cupolas_file_dirname(const char *path, char *buf, size_t size)
{
    if (!path || !buf || size == 0)
        return NULL;

    size_t len = strlen(path);
    if (len >= size)
        return NULL;

    AIRY_STRNCPY_TERM(buf, path, size);

    char *last_slash = strrchr(buf, '/');
#if cupolas_PLATFORM_WINDOWS
    char *last_bs = strrchr(buf, '\\');
    if (last_bs > last_slash)
        last_slash = last_bs;
#endif

    if (last_slash) {
        *last_slash = '\0';
    } else {
        buf[0] = '.';
        buf[1] = '\0';
    }
    return buf;
}
