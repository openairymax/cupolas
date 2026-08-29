/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * Thread / Mutex / RWLock / Condvar primitives (cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_THREAD_H
#define cupolas_PLATFORM_THREAD_H

#include "platform_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Thread Primitives
 * ============================================================================ */

/* Thread Handle Types */
#if cupolas_PLATFORM_WINDOWS
#include "atomic_compat.h"

#include <windows.h>
typedef HANDLE cupolas_thread_t;
typedef DWORD cupolas_thread_id_t;
typedef CRITICAL_SECTION cupolas_mutex_t;
typedef struct {
    SRWLOCK lock;
    atomic_long state;
} cupolas_rwlock_t;
typedef CONDITION_VARIABLE cupolas_cond_t;
#else
#include <pthread.h>
#include <sys/types.h>
typedef pthread_t cupolas_thread_t;
typedef pthread_t cupolas_thread_id_t;
typedef pthread_mutex_t cupolas_mutex_t;
typedef pthread_rwlock_t cupolas_rwlock_t;
typedef pthread_cond_t cupolas_cond_t;
#endif

/* Mutex Interface */
/**
 * @brief Initialize mutex
 * @param[out] mutex Mutex handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership mutex: callee initializes
 */
int cupolas_mutex_init(cupolas_mutex_t *mutex);

/**
 * @brief Destroy mutex
 * @param[in] mutex Mutex handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: No, ensure no threads hold the lock
 * @reentrant N/A
 * @ownership mutex: caller transfers ownership
 */
int cupolas_mutex_destroy(cupolas_mutex_t *mutex);

/**
 * @brief Lock mutex
 * @param[in] mutex Mutex handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No (deadlock if same thread locks twice)
 */
int cupolas_mutex_lock(cupolas_mutex_t *mutex);

/**
 * @brief Try lock mutex
 * @param[in] mutex Mutex handle (must not be NULL)
 * @return 0 on success, cupolas_ERROR_BUSY if already locked, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No
 */
int cupolas_mutex_trylock(cupolas_mutex_t *mutex);

/**
 * @brief Unlock mutex
 * @param[in] mutex Mutex handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No (only owner should unlock)
 */
int cupolas_mutex_unlock(cupolas_mutex_t *mutex);

/* Read-Write Lock Interface */
/**
 * @brief Initialize read-write lock
 * @param[out] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership rwlock: callee initializes
 */
int cupolas_rwlock_init(cupolas_rwlock_t *rwlock);

/**
 * @brief Destroy read-write lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: No
 * @reentrant N/A
 * @ownership rwlock: caller transfers ownership
 */
int cupolas_rwlock_destroy(cupolas_rwlock_t *rwlock);

/**
 * @brief Acquire read lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes (same thread can acquire multiple read locks)
 */
int cupolas_rwlock_rdlock(cupolas_rwlock_t *rwlock);

/**
 * @brief Acquire write lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No
 */
int cupolas_rwlock_wrlock(cupolas_rwlock_t *rwlock);

/**
 * @brief Try acquire read lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, cupolas_ERROR_BUSY if write locked, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_rwlock_tryrdlock(cupolas_rwlock_t *rwlock);

/**
 * @brief Try acquire write lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, cupolas_ERROR_BUSY if locked, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No
 */
int cupolas_rwlock_trywrlock(cupolas_rwlock_t *rwlock);

/**
 * @brief Unlock read-write lock
 * @param[in] rwlock Read-write lock handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_rwlock_unlock(cupolas_rwlock_t *rwlock);

/* Condition Variable Interface */
/**
 * @brief Initialize condition variable
 * @param[out] cond Condition variable handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership cond: callee initializes
 */
int cupolas_cond_init(cupolas_cond_t *cond);

/**
 * @brief Destroy condition variable
 * @param[in] cond Condition variable handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: No
 * @reentrant N/A
 * @ownership cond: caller transfers ownership
 */
int cupolas_cond_destroy(cupolas_cond_t *cond);

/**
 * @brief Wait for condition
 * @param[in] cond Condition variable handle (must not be NULL)
 * @param[in] mutex Associated mutex (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No
 * @post Atomically releases mutex and waits, then reacquires mutex on wake
 */
int cupolas_cond_wait(cupolas_cond_t *cond, cupolas_mutex_t *mutex);

/**
 * @brief Wait for condition with timeout
 * @param[in] cond Condition variable handle (must not be NULL)
 * @param[in] mutex Associated mutex (must not be NULL)
 * @param[in] timeout_ms Timeout in milliseconds
 * @return 0 on success, cupolas_ERROR_TIMEOUT on timeout, negative on failure
 * @note Thread-safe: Yes
 * @reentrant No
 */
int cupolas_cond_timedwait(cupolas_cond_t *cond, cupolas_mutex_t *mutex, uint32_t timeout_ms);

/**
 * @brief Signal condition variable (wake one)
 * @param[in] cond Condition variable handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_cond_signal(cupolas_cond_t *cond);

/**
 * @brief Broadcast condition variable (wake all)
 * @param[in] cond Condition variable handle (must not be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
int cupolas_cond_broadcast(cupolas_cond_t *cond);

/* Thread Interface */
typedef void *(*cupolas_thread_func_t)(void *arg);

/**
 * @brief Create thread
 * @param[out] thread Thread handle output (must not be NULL)
 * @param[in] func Thread function (must not be NULL)
 * @param[in] arg Argument passed to thread function
 * @return 0 on success, negative on failure
 * @note Thread-safe: N/A
 * @reentrant N/A
 * @ownership thread: callee initializes, caller owns
 */
int cupolas_thread_create(cupolas_thread_t *thread, cupolas_thread_func_t func, void *arg);

/**
 * @brief Join thread
 * @param[in] thread Thread handle
 * @param[out] retval Return value from thread function (may be NULL)
 * @return 0 on success, negative on failure
 * @note Thread-safe: No
 * @reentrant N/A
 * @ownership retval: callee writes if not NULL, caller owns
 */
int cupolas_thread_join(cupolas_thread_t thread, void **retval);

/**
 * @brief Detach thread
 * @param[in] thread Thread handle
 * @return 0 on success, negative on failure
 * @note Thread-safe: No
 * @reentrant N/A
 */
int cupolas_thread_detach(cupolas_thread_t thread);

/**
 * @brief Get current thread ID
 * @return Current thread ID
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
cupolas_thread_id_t cupolas_thread_self(void);

/**
 * @brief Compare thread IDs
 * @param[in] t1 First thread ID
 * @param[in] t2 Second thread ID
 * @return true if equal, false otherwise
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
bool cupolas_thread_equal(cupolas_thread_id_t t1, cupolas_thread_id_t t2);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_THREAD_H */
