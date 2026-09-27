/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * platform.h - Cross-Platform Abstraction Layer: Unified Windows/POSIX Differences
 *
 * Design Principles:
 * - Single Responsibility: Only handles platform differences
 * - Zero Overhead: Inline functions + macro definitions
 * - Type Safety: Strong type encapsulation
 */

#ifndef cupolas_PLATFORM_BASE_H
#define cupolas_PLATFORM_BASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Detection
 * ============================================================================ */

#if defined(_WIN32) || defined(_WIN64)
#define cupolas_PLATFORM_WINDOWS 1
#define cupolas_PLATFORM_POSIX 0
#ifdef _WIN64
#define cupolas_PLATFORM_64BIT 1
#else
#define cupolas_PLATFORM_64BIT 0
#endif
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#define cupolas_PLATFORM_WINDOWS 0
#define cupolas_PLATFORM_POSIX 1
/* SSoT: 与 commons/platform.h 一致，使用 UINTPTR_MAX 判断 64 位，
 * 覆盖 x86_64/aarch64/riscv64/ppc64/s390x 等全部 64 位架构。 */
#if UINTPTR_MAX == UINT64_MAX
#define cupolas_PLATFORM_64BIT 1
#else
#define cupolas_PLATFORM_64BIT 0
#endif
#else
#error "Unsupported platform"
#endif

/* ============================================================================
 * Export Macros
 * ============================================================================ */

#if cupolas_PLATFORM_WINDOWS
#ifdef cupolas_BUILD_DLL
#define cupolas_API __declspec(dllexport)
#else
#define cupolas_API __declspec(dllimport)
#endif
#else
#define cupolas_API __attribute__((visibility("default")))
#endif


/* ============================================================================
 * Utility Macros
 * ============================================================================ */

/* Unused Parameter Marker */
#ifndef cupolas_UNUSED
#define cupolas_UNUSED(x) ((void)(x))
#endif


/* ============================================================================
 * Error Handling
 * ============================================================================ */

/* SSoT: 错误码别名宏唯一定义点为 cupolas_error.h。
 * 历史上本头文件曾硬编码 -1..-11 旧错误码（与 commons 权威值错位，
 * WOULD_BLOCK=-8 与 TIMEOUT 撞号），已整体移除。 */
#include "../security/cupolas_error.h"

/**
 * @brief Get last error code
 * @return Last error code
 * @note Thread-safe: Yes (per-thread errno-style)
 * @reentrant Yes
 */
int cupolas_get_last_error(void);

/**
 * @brief Get error string
 * @param[in] error Error code
 * @return Error description string (static, do not free)
 * @note Thread-safe: Yes
 * @reentrant Yes
 */
const char *cupolas_strerror(int error);


#ifdef __cplusplus
}
#endif

#endif /* cupolas_PLATFORM_BASE_H */
