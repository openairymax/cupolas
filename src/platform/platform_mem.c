// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform_mem.c - Cross-Platform Abstraction Layer (Memory and Atomic)
 */

/**
 * @file platform_mem.c
 * @brief cupolas 平台抽象层 - 内存与原子操作域
 *
 * 本文件实现内存分配/对齐/释放/零化/锁页与 32/64 位原子操作。
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
 * Memory Implementation
 * ============================================================================ */

void *cupolas_mem_alloc(size_t size)
{
    if (size == 0)
        return NULL;
#if cupolas_PLATFORM_WINDOWS
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
#else
    void *ptr = AIRY_MALLOC(size);
    if (ptr)
        __builtin_memset(ptr, 0, size);
    return ptr;
#endif
}

void *cupolas_mem_alloc_aligned(size_t size, size_t alignment)
{
    if (size == 0 || alignment == 0)
        return NULL;
#if cupolas_PLATFORM_WINDOWS
    return _aligned_malloc(size, alignment);
#else
    void *ptr = NULL;
    int ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0)
        return NULL;
    return ptr;
#endif
}

void cupolas_mem_free(void *ptr)
{
    if (!ptr)
        return;
#if cupolas_PLATFORM_WINDOWS
    HeapFree(GetProcessHeap(), 0, ptr);
#else
    AIRY_FREE(ptr);
#endif
}

void *cupolas_mem_realloc(void *ptr, size_t size)
{
#if cupolas_PLATFORM_WINDOWS
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size);
#else
    return AIRY_REALLOC(ptr, size);
#endif
}

void cupolas_mem_zero(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return;
#if cupolas_PLATFORM_WINDOWS
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size--)
        *p++ = 0;
#endif
}

void cupolas_mem_lock(void *ptr, size_t size)
{
#if cupolas_PLATFORM_WINDOWS
    VirtualLock(ptr, size);
#else
    if (ptr && size > 0)
        mlock(ptr, size);
#endif
}

void cupolas_mem_unlock(void *ptr, size_t size)
{
#if cupolas_PLATFORM_WINDOWS
    VirtualUnlock(ptr, size);
#else
    if (ptr && size > 0)
        munlock(ptr, size);
#endif
}

/* ============================================================================
 * Atomic Operations Implementation
 * ============================================================================ */

int32_t cupolas_atomic_load32(volatile int32_t *ptr)
{
    return (int32_t)atomic_load_32((volatile _Atomic int *)ptr, memory_order_seq_cst);
}

void cupolas_atomic_store32(volatile int32_t *ptr, int32_t val)
{
    atomic_store_32((volatile _Atomic int *)ptr, (int)val, memory_order_seq_cst);
}

int32_t cupolas_atomic_add32(volatile int32_t *ptr, int32_t delta)
{
    return (int32_t)(atomic_fetch_add_32((volatile _Atomic int *)ptr, (int)delta,
                                         memory_order_seq_cst) +
                     delta);
}

int32_t cupolas_atomic_sub32(volatile int32_t *ptr, int32_t delta)
{
    return cupolas_atomic_add32(ptr, -delta);
}

int32_t cupolas_atomic_inc32(volatile int32_t *ptr)
{
    return cupolas_atomic_add32(ptr, 1);
}

int32_t cupolas_atomic_dec32(volatile int32_t *ptr)
{
    return cupolas_atomic_sub32(ptr, 1);
}

bool cupolas_atomic_cas32(volatile int32_t *ptr, int32_t expected, int32_t desired)
{
    int exp = (int)expected;
    return atomic_compare_exchange_strong_32((volatile _Atomic int *)ptr, &exp, (int)desired,
                                             memory_order_seq_cst, memory_order_seq_cst);
}

int64_t cupolas_atomic_load64(volatile int64_t *ptr)
{
    return atomic_load_64((volatile _Atomic int64_t *)ptr, memory_order_seq_cst);
}

void cupolas_atomic_store64(volatile int64_t *ptr, int64_t val)
{
    atomic_store_64((volatile _Atomic int64_t *)ptr, val, memory_order_seq_cst);
}

int64_t cupolas_atomic_add64(volatile int64_t *ptr, int64_t delta)
{
    return atomic_fetch_add_64((volatile _Atomic int64_t *)ptr, delta, memory_order_seq_cst) +
           delta;
}

int64_t cupolas_atomic_sub64(volatile int64_t *ptr, int64_t delta)
{
    return cupolas_atomic_add64(ptr, -delta);
}

bool cupolas_atomic_cas64(volatile int64_t *ptr, int64_t expected, int64_t desired)
{
    int64_t exp = expected;
    return atomic_compare_exchange_strong_64((volatile _Atomic int64_t *)ptr, &exp, desired,
                                             memory_order_seq_cst, memory_order_seq_cst);
}

void *cupolas_atomic_load_ptr(volatile void **ptr)
{
    return atomic_load_ptr((atomic_void_ptr_t *)ptr, memory_order_seq_cst);
}

void cupolas_atomic_store_ptr(volatile void **ptr, void *val)
{
    atomic_store_ptr((atomic_void_ptr_t *)ptr, val, memory_order_seq_cst);
}

bool cupolas_atomic_cas_ptr(volatile void **ptr, void *expected, void *desired)
{
    return atomic_compare_exchange_strong_ptr((atomic_void_ptr_t *)ptr, &expected, desired,
                                              memory_order_seq_cst, memory_order_seq_cst);
}
