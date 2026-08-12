// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform_util.c - Cross-Platform Abstraction Layer (Error and String)
 */

/**
 * @file platform_util.c
 * @brief cupolas 平台抽象层 - 错误与字符串工具域
 *
 * 本文件实现最后错误查询、错误描述转换与字符串复制/比较工具。
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
 * Error Handling Implementation
 * ============================================================================ */

int cupolas_get_last_error(void)
{
#if cupolas_PLATFORM_WINDOWS
    return (int)GetLastError();
#else
    return errno;
#endif
}

const char *cupolas_strerror(int error)
{
    switch (error) {
    case 0:
        return "Success";
    case cupolas_ERROR_UNKNOWN:
        return "Unknown error";
    case cupolas_ERROR_INVALID_ARG:
        return "Invalid argument";
    case cupolas_ERROR_NO_MEMORY:
        return "Out of memory";
    case cupolas_ERROR_NOT_FOUND:
        return "Not found";
    case cupolas_ERROR_PERMISSION:
        return "Permission denied";
    case cupolas_ERROR_BUSY:
        return "Resource busy";
    case cupolas_ERROR_TIMEOUT:
        return "Operation timed out";
    case cupolas_ERROR_WOULD_BLOCK:
        return "Operation would block";
    case cupolas_ERROR_OVERFLOW:
        return "Overflow";
    case cupolas_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case cupolas_ERROR_IO:
        return "I/O error";
    default:
#if cupolas_PLATFORM_WINDOWS
        static char msg[256];
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, (DWORD)error, 0, msg, sizeof(msg), NULL);
        return msg;
#else
        return strerror(error);
#endif
    }
}

/* ============================================================================
 * String Utilities Implementation
 * ============================================================================ */

char *cupolas_strdup(const char *str)
{
    if (!str)
        return NULL;
    size_t len = strlen(str) + 1;
    char *dup = (char *)cupolas_mem_alloc(len);
    if (dup)
        __builtin_memcpy(dup, str, len);
    return dup;
}

char *cupolas_strndup(const char *str, size_t n)
{
    if (!str)
        return NULL;
    size_t len = strlen(str);
    if (len > n)
        len = n;
    char *dup = (char *)cupolas_mem_alloc(len + 1);
    if (dup) {
        __builtin_memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}

int cupolas_strcasecmp(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return (s1 ? 1 : (s2 ? -1 : 0));
#if cupolas_PLATFORM_WINDOWS
    return _stricmp(s1, s2);
#else
    return strcasecmp(s1, s2);
#endif
}

int cupolas_strncasecmp(const char *s1, const char *s2, size_t n)
{
    if (!s1 || !s2)
        return (s1 ? 1 : (s2 ? -1 : 0));
#if cupolas_PLATFORM_WINDOWS
    return _strnicmp(s1, s2, n);
#else
    return strncasecmp(s1, s2, n);
#endif
}
