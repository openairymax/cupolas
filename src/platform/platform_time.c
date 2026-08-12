// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform_time.c - Cross-Platform Abstraction Layer (Time)
 */

/**
 * @file platform_time.c
 * @brief cupolas 平台抽象层 - 时间域
 *
 * 本文件实现实时/单调时钟、毫秒时间戳与睡眠接口。
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
 * Time Implementation
 * ============================================================================ */

int cupolas_time_now(cupolas_timestamp_t *ts)
{
    if (!ts)
        return cupolas_ERROR_INVALID_ARG;
#if cupolas_PLATFORM_WINDOWS
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uint64_t ns100 = uli.QuadPart;
    ts->sec = (int64_t)(ns100 / 10000000ULL - 11644473600ULL);
    ts->nsec = (int32_t)((ns100 % 10000000ULL) * 100);
    return 0;
#else
    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0)
        return cupolas_ERROR_IO;
    ts->sec = tp.tv_sec;
    ts->nsec = tp.tv_nsec;
    return 0;
#endif
}

int cupolas_time_mono(cupolas_timestamp_t *ts)
{
    if (!ts)
        return cupolas_ERROR_INVALID_ARG;
#if cupolas_PLATFORM_WINDOWS
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    uint64_t ns = (uint64_t)(counter.QuadPart * 1000000000ULL / freq.QuadPart);
    ts->sec = (int64_t)(ns / 1000000000ULL);
    ts->nsec = (int32_t)(ns % 1000000000ULL);
    return 0;
#else
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
        return cupolas_ERROR_IO;
    ts->sec = tp.tv_sec;
    ts->nsec = tp.tv_nsec;
    return 0;
#endif
}

uint64_t cupolas_time_ms(void)
{
#if cupolas_PLATFORM_WINDOWS
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uint64_t)((uli.QuadPart / 10000ULL) - 11644473600000ULL);
#else
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    return (uint64_t)tp.tv_sec * 1000ULL + (uint64_t)tp.tv_nsec / 1000000ULL;
#endif
}

void cupolas_sleep_ms(uint32_t ms)
{
#if cupolas_PLATFORM_WINDOWS
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

void cupolas_sleep_us(uint32_t us)
{
#if cupolas_PLATFORM_WINDOWS
    if (us < 1000) {
        Sleep(1);
    } else {
        Sleep(us / 1000);
    }
#else
    usleep(us);
#endif
}
