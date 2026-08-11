/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/**
 * @file mempool.h
 * @brief P3.16: mempool 最小保证分配器 — 紧急预留 + 对象池 + 最低保证分配
 *
 * 在 OOM 场景下保证 IPC 消息等关键路径的内存分配。
 * 核心特性：
 *   - 紧急预留池（默认 32MB）
 *   - 对象池（固定大小对象快速分配）
 *   - 最低保证分配（OOM 时优先满足关键路径）
 *   - 分级水位线（正常/警告/紧急）
 *
 * 典型用法：
 *   airy_mempool_t *pool = airy_mempool_create(32 * 1024 * 1024, 256, 1024);
 *   void *buf = airy_mempool_alloc(pool, 512, MEMPOOL_PRIORITY_CRITICAL);
 *   // ... 使用 buf ...
 *   airy_mempool_free(pool, buf);
 *   airy_mempool_destroy(pool);
 *
 */

#ifndef CUPOLAS_MEMPOOL_H
#define CUPOLAS_MEMPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量定义
 * ================================================================ */


#define MEMPOOL_DEFAULT_RESERVE_MB 32

#define MEMPOOL_DEFAULT_BLOCK_SIZE 256

#define MEMPOOL_DEFAULT_BLOCK_COUNT 4096

/* ================================================================
 * 类型定义
 * ================================================================ */


typedef struct airy_mempool airy_mempool_t;


typedef enum {
    MEMPOOL_PRIORITY_LOW = 0,
    MEMPOOL_PRIORITY_NORMAL = 1,
    MEMPOOL_PRIORITY_HIGH = 2,
    MEMPOOL_PRIORITY_CRITICAL = 3,
} airy_mempool_priority_t;


typedef enum {
    MEMPOOL_WATERMARK_NORMAL = 0,
    MEMPOOL_WATERMARK_WARN = 1,
    MEMPOOL_WATERMARK_HIGH = 2,
    MEMPOOL_WATERMARK_CRITICAL = 3,
} airy_mempool_watermark_t;


typedef struct {
    size_t total_reserved;
    size_t total_allocated;
    size_t peak_allocated;
    size_t available_reserved;
    size_t object_pool_total;
    size_t object_pool_used;
    size_t total_allocs;
    size_t total_frees;
    size_t oom_rejections;
    size_t emergency_allocs;
    airy_mempool_watermark_t watermark;
} airy_mempool_stats_t;

/* ================================================================
 * 生命周期 API
 * ================================================================ */

/**
 * @brief 创建内存池
 *
 * @param reserve_size   紧急预留大小（字节），0 使用默认 32MB
 * @param block_size     对象池块大小（字节），0 使用默认 256B
 * @param block_count    对象池块数量，0 使用默认 4096
 * @return 内存池句柄，失败返回 NULL
 *
 * @ownership 返回的句柄由调用者管理，需通过 airy_mempool_destroy() 释放
 * @threadsafe 是
 */
airy_mempool_t *airy_mempool_create(size_t reserve_size, size_t block_size, size_t block_count);

/**
 * @brief 销毁内存池
 *
 * 释放所有预留内存和对象池。
 *
 * @param pool 内存池句柄
 *
 * @ownership pool: TRANSFER
 * @threadsafe 否
 */
void airy_mempool_destroy(airy_mempool_t *pool);

/* ================================================================
 * 分配/释放 API
 * ================================================================ */

/**
 * @brief 从内存池分配内存
 *
 * 分配策略：
 *   - 等于 block_size 的分配 → 优先从对象池获取
 *   - 其他大小 → 从预留池分配
 *   - 优先级 CRITICAL → OOM 时仍保证分配（从紧急预留取）
 *   - 水位线告警时 → 低优先级分配可能被拒绝
 *
 * @param pool     内存池句柄
 * @param size     分配大小（字节）
 * @param priority 分配优先级
 * @return 内存指针，失败返回 NULL
 *
 * @ownership 返回的内存由调用者管理，需通过 airy_mempool_free() 归还
 * @threadsafe 是
 */
void *airy_mempool_alloc(airy_mempool_t *pool, size_t size, airy_mempool_priority_t priority);

/**
 * @brief 释放内存回内存池
 *
 * @param pool 内存池句柄
 * @param ptr  内存指针（NULL 无操作）
 *
 * @ownership ptr: TRANSFER
 * @threadsafe 是
 */
void airy_mempool_free(airy_mempool_t *pool, void *ptr);

/* ================================================================
 * 统计与诊断 API
 * ================================================================ */

/**
 * @brief 获取内存池统计信息
 *
 * @param pool  内存池句柄
 * @param stats 输出统计信息
 * @return 0 成功，非0失败
 */
int airy_mempool_get_stats(airy_mempool_t *pool, airy_mempool_stats_t *stats);

/**
 * @brief 获取当前水位线
 *
 * @param pool 内存池句柄
 * @return 当前水位线状态
 */
airy_mempool_watermark_t airy_mempool_get_watermark(airy_mempool_t *pool);

/**
 * @brief 收缩内存池：释放空闲对象池块
 *
 * @param pool 内存池句柄
 * @return 释放的块数
 */
size_t airy_mempool_shrink(airy_mempool_t *pool);

/**
 * @brief 验证内存池内部一致性
 *
 * @param pool 内存池句柄
 * @return true 一致，false 损坏
 */
bool airy_mempool_validate(airy_mempool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_MEMPOOL_H */