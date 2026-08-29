/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * One-time initialization (cross-platform).
 * Split from platform.h (0.1.6 大文件拆分).
 */

#ifndef cupolas_PLATFORM_ONCE_H
#define cupolas_PLATFORM_ONCE_H

#include "platform_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * One-Time Initialization
 * ============================================================================ */

#if cupolas_PLATFORM_WINDOWS
typedef INIT_ONCE cupolas_once_t;
#define CUPOLAS_ONCE_INIT INIT_ONCE_STATIC_INIT
#else
typedef pthread_once_t cupolas_once_t;
#define CUPOLAS_ONCE_INIT PTHREAD_ONCE_INIT
#endif

static inline void cupolas_call_once(cupolas_once_t *once, void (*func)(void))
{
#if cupolas_PLATFORM_WINDOWS
    InitOnceExecuteOnce(once, (PINIT_ONCE_FN)(void *)func, NULL, NULL);
#else
    pthread_once(once, func);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_ONCE_H */
