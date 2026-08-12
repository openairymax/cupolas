// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * platform.c - Cross-Platform Abstraction Layer Implementation (Sync Primitives)
 *
 * Self-contained implementation using OS primitives directly.
 * No dependency on agentrt/commons/platform_adapter (which only provides
 * high-level file/path/env utilities, not sync primitives).
 */

/**
 * @file platform.c
 * @brief cupolas 平台抽象层 - 同步原语域
 *
 * 本文件保留平台抽象层的核心状态机：互斥锁、读写锁、条件变量与线程。
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
 * Mutex Implementation
 * ============================================================================ */

int cupolas_mutex_init(cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    InitializeCriticalSection(mutex);
    return 0;
#else
    return pthread_mutex_init(mutex, NULL) == 0 ? 0 : -1;
#endif
}

int cupolas_mutex_destroy(cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    DeleteCriticalSection(mutex);
    return 0;
#else
    return pthread_mutex_destroy(mutex) == 0 ? 0 : -1;
#endif
}

int cupolas_mutex_lock(cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    EnterCriticalSection(mutex);
    return 0;
#else
    return pthread_mutex_lock(mutex) == 0 ? 0 : -1;
#endif
}

int cupolas_mutex_trylock(cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    return TryEnterCriticalSection(mutex) ? 0 : cupolas_ERROR_BUSY;
#else
    int ret = pthread_mutex_trylock(mutex);
    if (ret == 0)
        return 0;
    if (ret == EBUSY)
        return cupolas_ERROR_BUSY;
    return AIRY_EINVAL;
#endif
}

int cupolas_mutex_unlock(cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    LeaveCriticalSection(mutex);
    return 0;
#else
    return pthread_mutex_unlock(mutex) == 0 ? 0 : -1;
#endif
}

/* ============================================================================
 * Read-Write Lock Implementation
 * ============================================================================ */

int cupolas_rwlock_init(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    InitializeSRWLock(&rwlock->lock);
    rwlock->state = 0;
    return 0;
#else
    return pthread_rwlock_init(rwlock, NULL) == 0 ? 0 : -1;
#endif
}

int cupolas_rwlock_destroy(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    rwlock->state = 0;
    (void)rwlock;
    return 0;
#else
    return pthread_rwlock_destroy(rwlock) == 0 ? 0 : -1;
#endif
}

int cupolas_rwlock_rdlock(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    AcquireSRWLockShared(&rwlock->lock);
    atomic_fetch_add_32(&rwlock->state, 1, memory_order_seq_cst);
    return 0;
#else
    return pthread_rwlock_rdlock(rwlock) == 0 ? 0 : -1;
#endif
}

int cupolas_rwlock_wrlock(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    AcquireSRWLockExclusive(&rwlock->lock);
    atomic_exchange_32(&rwlock->state, -1, memory_order_seq_cst);
    return 0;
#else
    return pthread_rwlock_wrlock(rwlock) == 0 ? 0 : -1;
#endif
}

int cupolas_rwlock_tryrdlock(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    if (!TryAcquireSRWLockShared(&rwlock->lock))
        return cupolas_ERROR_BUSY;
    atomic_fetch_add_32(&rwlock->state, 1, memory_order_seq_cst);
    return 0;
#else
    int ret = pthread_rwlock_tryrdlock(rwlock);
    if (ret == 0)
        return 0;
    if (ret == EBUSY)
        return cupolas_ERROR_BUSY;
    return AIRY_EINVAL;
#endif
}

int cupolas_rwlock_trywrlock(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    if (!TryAcquireSRWLockExclusive(&rwlock->lock))
        return cupolas_ERROR_BUSY;
    atomic_exchange_32(&rwlock->state, -1, memory_order_seq_cst);
    return 0;
#else
    int ret = pthread_rwlock_trywrlock(rwlock);
    if (ret == 0)
        return 0;
    if (ret == EBUSY)
        return cupolas_ERROR_BUSY;
    return AIRY_EINVAL;
#endif
}

int cupolas_rwlock_unlock(cupolas_rwlock_t *rwlock)
{
#if cupolas_PLATFORM_WINDOWS
    long s = atomic_fetch_add_32(&rwlock->state, 0, memory_order_seq_cst);
    if (s < 0) {
        atomic_exchange_32(&rwlock->state, 0, memory_order_seq_cst);
        ReleaseSRWLockExclusive(&rwlock->lock);
    } else {
        atomic_fetch_sub_32(&rwlock->state, 1, memory_order_seq_cst);
        ReleaseSRWLockShared(&rwlock->lock);
    }
    return 0;
#else
    return pthread_rwlock_unlock(rwlock) == 0 ? 0 : -1;
#endif
}

/* ============================================================================
 * Condition Variable Implementation
 * ============================================================================ */

int cupolas_cond_init(cupolas_cond_t *cond)
{
#if cupolas_PLATFORM_WINDOWS
    InitializeConditionVariable(cond);
    return 0;
#else
    return pthread_cond_init(cond, NULL) == 0 ? 0 : -1;
#endif
}

int cupolas_cond_destroy(cupolas_cond_t *cond)
{
#if cupolas_PLATFORM_WINDOWS
    /* CONDITION_VARIABLE does not need destruction */
    (void)cond;
    return 0;
#else
    return pthread_cond_destroy(cond) == 0 ? 0 : -1;
#endif
}

int cupolas_cond_wait(cupolas_cond_t *cond, cupolas_mutex_t *mutex)
{
#if cupolas_PLATFORM_WINDOWS
    return SleepConditionVariableCS(cond, mutex, INFINITE) ? 0 : -1;
#else
    return pthread_cond_wait(cond, mutex) == 0 ? 0 : -1;
#endif
}

int cupolas_cond_timedwait(cupolas_cond_t *cond, cupolas_mutex_t *mutex, uint32_t timeout_ms)
{
#if cupolas_PLATFORM_WINDOWS
    if (!SleepConditionVariableCS(cond, mutex, timeout_ms))
        return cupolas_ERROR_TIMEOUT;
    return 0;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (timeout_ms / 1000);
    ts.tv_nsec += ((timeout_ms % 1000) * 1000000);
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_nsec -= 1000000000;
        ts.tv_sec++;
    }
    int ret = pthread_cond_timedwait(cond, mutex, &ts);
    if (ret == 0)
        return 0;
    if (ret == ETIMEDOUT)
        return cupolas_ERROR_TIMEOUT;
    return AIRY_EINVAL;
#endif
}

int cupolas_cond_signal(cupolas_cond_t *cond)
{
#if cupolas_PLATFORM_WINDOWS
    WakeConditionVariable(cond);
    return 0;
#else
    return pthread_cond_signal(cond) == 0 ? 0 : -1;
#endif
}

int cupolas_cond_broadcast(cupolas_cond_t *cond)
{
#if cupolas_PLATFORM_WINDOWS
    WakeAllConditionVariable(cond);
    return 0;
#else
    return pthread_cond_broadcast(cond) == 0 ? 0 : -1;
#endif
}

/* ============================================================================
 * Thread Implementation
 * ============================================================================ */

typedef struct thread_wrapper_arg {
    cupolas_thread_func_t func;
    void *arg;
} thread_wrapper_arg_t;

#if !cupolas_PLATFORM_WINDOWS
static void *thread_wrapper(void *arg)
{
    thread_wrapper_arg_t *wrapper = (thread_wrapper_arg_t *)arg;
    cupolas_thread_func_t func = wrapper->func;
    void *user_arg = wrapper->arg;
    AIRY_FREE(wrapper);
    return func(user_arg);
}
#endif

int cupolas_thread_create(cupolas_thread_t *thread, cupolas_thread_func_t func, void *arg)
{
#if cupolas_PLATFORM_WINDOWS
    thread_wrapper_arg_t *wrapper =
        (thread_wrapper_arg_t *)AIRY_MALLOC(sizeof(thread_wrapper_arg_t));
    if (!wrapper)
        return cupolas_ERROR_NO_MEMORY;
    wrapper->func = func;
    wrapper->arg = arg;

    *thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(void (*)(void *))func, arg, 0, NULL);
    if (*thread == NULL) {
        AIRY_FREE(wrapper);
        return cupolas_ERROR_UNKNOWN;
    }
    AIRY_FREE(wrapper);
    return 0;
#else
    thread_wrapper_arg_t *wrapper =
        (thread_wrapper_arg_t *)AIRY_MALLOC(sizeof(thread_wrapper_arg_t));
    if (!wrapper)
        return cupolas_ERROR_NO_MEMORY;
    wrapper->func = func;
    wrapper->arg = arg;

    int ret = pthread_create(thread, NULL, thread_wrapper, wrapper);
    if (ret != 0) {
        AIRY_FREE(wrapper);
        return AIRY_EINVAL;
    }
    return 0;
#endif
}

int cupolas_thread_join(cupolas_thread_t thread, void **retval)
{
#if cupolas_PLATFORM_WINDOWS
    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    if (retval)
        *retval = (void *)(uintptr_t)exit_code;
    return 0;
#else
    return pthread_join(thread, retval) == 0 ? 0 : -1;
#endif
}

int cupolas_thread_detach(cupolas_thread_t thread)
{
#if cupolas_PLATFORM_WINDOWS
    CloseHandle(thread);
    return 0;
#else
    return pthread_detach(thread) == 0 ? 0 : -1;
#endif
}

cupolas_thread_id_t cupolas_thread_self(void)
{
#if cupolas_PLATFORM_WINDOWS
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif
}

bool cupolas_thread_equal(cupolas_thread_id_t t1, cupolas_thread_id_t t2)
{
#if cupolas_PLATFORM_WINDOWS
    return t1 == t2;
#else
    return pthread_equal(t1, t2);
#endif
}
