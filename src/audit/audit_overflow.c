// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "atomic_compat.h"
#include "cupolas.h"
/*
 *
 * audit_overflow.c - 审计溢出处理器：背压分级、回调与生命周期
 *
 * 落盘域（命名/目录/序列化/打开）见 audit_overflow_io.c。
 */

#include "audit_overflow_internal.h"

#include "airy_memory.h"
#include "platform.h"
#include "security/cupolas_error.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>

#include "error.h"

/* A-5：默认惰性创建——零溢出事件不得留下 0 字节 audit_overflow_*.log。
 * AIRY_PREOPEN_OVERFLOW=1 恢复旧行为（创建即 fopen），仅排障用。 */
static int overflow_preopen_enabled(void)
{
    const char *env = getenv("AIRY_PREOPEN_OVERFLOW");
    return env && env[0] == '1';
}

static void *flush_thread_func(void *arg)
{
    overflow_handler_t *handler = (overflow_handler_t *)arg;

    while (handler->running) {
        airy_sleep_ms(handler->flush_interval_ms);

        airy_mtx_lock(&handler->lock);

        if (handler->current_file) {
            fflush(handler->current_file);
            handler->stats.last_flush_time_ms = airy_time_wall_ms();
        }

        airy_mtx_unlock(&handler->lock);
    }

    return NULL;
}

overflow_handler_t *overflow_handler_create(const char *overflow_dir, size_t max_file_size_mb,
                                            uint32_t flush_interval_ms)
{
    overflow_handler_t *handler =
        (overflow_handler_t *)AIRY_CALLOC(1, sizeof(overflow_handler_t));
    if (!handler)
        return NULL;

    __builtin_memset(handler, 0, sizeof(overflow_handler_t));

    /* R-6 同族缺陷：默认溢出目录走运行期 AIRY_HOME 路径系统。 */
    char default_overflow_dir[512];
    snprintf(default_overflow_dir, sizeof(default_overflow_dir), "%s/cupolas", airy_log_dir());
    snprintf(handler->overflow_dir, sizeof(handler->overflow_dir), "%s",
             overflow_dir ? overflow_dir : default_overflow_dir);
    handler->max_file_size_bytes =
        (max_file_size_mb > 0 ? max_file_size_mb : DEFAULT_MAX_FILE_SIZE_MB) * 1024 * 1024;
    handler->flush_interval_ms =
        flush_interval_ms > 0 ? flush_interval_ms : DEFAULT_FLUSH_INTERVAL_MS;

    if (ovf_ensure_dir(handler->overflow_dir) != 0) {
        snprintf(handler->overflow_dir, sizeof(handler->overflow_dir),
                 AIRY_TMP_DIR "/cupolas_audit");
        ovf_ensure_dir(handler->overflow_dir);
    }

    if (airy_mtx_init(&handler->lock) != cupolas_OK) {
        AIRY_FREE(handler);
        return NULL;
    }

    /* A-5 惰性创建：默认不在 create 时落盘，首个真实溢出事件才开文件，
     * 避免「零事件也留 0 字节 audit_overflow_*.log」。
     * AIRY_PREOPEN_OVERFLOW=1 恢复旧行为，仅排障用。 */
    if (overflow_preopen_enabled() && ovf_open_new(handler) != 0) {
        airy_mtx_destroy(&handler->lock);
        AIRY_FREE(handler);
        return NULL;
    }

    handler->running = true;
    if (airy_platform_thread_create(&handler->flush_thread, flush_thread_func, handler) != cupolas_OK) {
        handler->running = false;
        if (handler->current_file)
            fclose(handler->current_file);
        airy_mtx_destroy(&handler->lock);
        AIRY_FREE(handler);
        return NULL;
    }

    return handler;
}

void overflow_handler_destroy(overflow_handler_t *handler)
{
    if (!handler)
        return;

    handler->running = false;

    if (handler->flush_thread) {
        airy_platform_thread_join(handler->flush_thread, NULL);
    }

    airy_mtx_lock(&handler->lock);

    if (handler->current_file) {
        fflush(handler->current_file);
        fclose(handler->current_file);
        handler->current_file = NULL;
    }

    airy_mtx_unlock(&handler->lock);

    airy_mtx_destroy(&handler->lock);
    AIRY_FREE(handler);
}

int overflow_handler_write(overflow_handler_t *handler, audit_entry_t *entry)
{
    if (!handler || !entry)
        AIRY_RET_ERR(AIRY_ERR_NULL_POINTER);

    airy_mtx_lock(&handler->lock);

    handler->total_events_received++;

    if (!handler->current_file || handler->current_file_size >= handler->max_file_size_bytes) {
        if (ovf_open_new(handler) != 0) {
            airy_mtx_unlock(&handler->lock);
            AIRY_RET_ERR(AIRY_ERR_IO);
        }
    }

    int written = ovf_write_entry(handler->current_file, entry);
    if (written < 0) {
        handler->disk_write_errors++;
        airy_mtx_unlock(&handler->lock);
        AIRY_RET_ERR(AIRY_ERR_IO);
    }

    handler->current_file_size += written;
    handler->events_written++;
    handler->stats.events_written_to_disk++;

    airy_mtx_unlock(&handler->lock);

    return 0;
}

void overflow_handler_flush(overflow_handler_t *handler)
{
    if (!handler)
        return;

    airy_mtx_lock(&handler->lock);

    if (handler->current_file) {
        fflush(handler->current_file);
        handler->stats.last_flush_time_ms = airy_time_wall_ms();
    }

    airy_mtx_unlock(&handler->lock);
}

void overflow_handler_get_stats(overflow_handler_t *handler, overflow_stats_t *stats)
{
    if (!handler || !stats)
        return;

    airy_mtx_lock(&handler->lock);

    stats->total_events_received = handler->total_events_received;
    stats->events_written_to_disk = handler->stats.events_written_to_disk;
    stats->events_dropped = handler->stats.events_dropped;
    stats->disk_write_errors = handler->disk_write_errors;
    stats->last_flush_time_ms = handler->stats.last_flush_time_ms;

    airy_mtx_unlock(&handler->lock);
}

void overflow_handler_reset_stats(overflow_handler_t *handler)
{
    if (!handler)
        return;

    airy_mtx_lock(&handler->lock);

    handler->total_events_received = 0;
    handler->stats.events_written_to_disk = 0;
    handler->stats.events_dropped = 0;
    handler->disk_write_errors = 0;

    airy_mtx_unlock(&handler->lock);
}

const char *overflow_get_dir(const overflow_handler_t *handler)
{
    return handler ? handler->overflow_dir : NULL;
}

overflow_level_t overflow_handler_check_level(size_t current_size, size_t max_size)
{
    if (max_size == 0)
        return OVERFLOW_LEVEL_SPILLING;

    double ratio = (double)current_size / (double)max_size;

    if (ratio >= 1.0)
        return OVERFLOW_LEVEL_SPILLING;
    if (ratio >= 0.95)
        return OVERFLOW_LEVEL_CRITICAL;
    if (ratio >= 0.80)
        return OVERFLOW_LEVEL_WARNING;

    return OVERFLOW_LEVEL_NORMAL;
}

int overflow_handler_set_callback(overflow_handler_t *handler, overflow_callback_t callback,
                                  void *user_data)
{
    if (!handler)
        AIRY_RET_ERR(AIRY_ERR_NULL_POINTER);

    handler->callback = callback;
    handler->callback_user_data = user_data;

    return 0;
}

struct audit_queue_ex {
    audit_queue_t *queue;
    overflow_handler_t *overflow;
    size_t max_size;
    overflow_callback_t overflow_callback;
    void *callback_user_data;
    atomic_int64_t total_dropped;
    overflow_level_t current_level;
    airy_mtx_t level_lock;
};

audit_queue_ex_t *audit_queue_ex_create(size_t max_size, const char *overflow_dir,
                                        size_t max_file_size_mb)
{
    audit_queue_ex_t *queue_ex = (audit_queue_ex_t *)AIRY_CALLOC(1, sizeof(audit_queue_ex_t));
    if (!queue_ex)
        return NULL;

    __builtin_memset(queue_ex, 0, sizeof(audit_queue_ex_t));

    queue_ex->queue = audit_queue_create(max_size);
    if (!queue_ex->queue) {
        AIRY_FREE(queue_ex);
        return NULL;
    }

    queue_ex->max_size = max_size;

    if (overflow_dir) {
        queue_ex->overflow = overflow_handler_create(overflow_dir, max_file_size_mb, 1000);
    }

    if (airy_mtx_init(&queue_ex->level_lock) != cupolas_OK) {
        if (queue_ex->overflow)
            overflow_handler_destroy(queue_ex->overflow);
        audit_queue_destroy(queue_ex->queue);
        AIRY_FREE(queue_ex);
        return NULL;
    }

    return queue_ex;
}

void audit_queue_ex_destroy(audit_queue_ex_t *queue)
{
    if (!queue)
        return;

    if (queue->overflow) {
        overflow_handler_destroy(queue->overflow);
    }

    audit_queue_destroy(queue->queue);

    airy_mtx_destroy(&queue->level_lock);

    AIRY_FREE(queue);
}

int audit_queue_ex_push(audit_queue_ex_t *queue, audit_entry_t *entry)
{
    return audit_queue_ex_push_with_callback(queue, entry, NULL, NULL);
}

int audit_queue_ex_push_with_callback(audit_queue_ex_t *queue, audit_entry_t *entry,
                                      overflow_callback_t callback, void *user_data)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    overflow_callback_t cb = callback ? callback : queue->overflow_callback;
    void *cb_user_data = user_data ? user_data : queue->callback_user_data;

    int result = audit_queue_try_push(queue->queue, entry);

    if (result == cupolas_ERROR_WOULD_BLOCK) {
        overflow_level_t level =
            overflow_handler_check_level(audit_queue_size(queue->queue), queue->max_size);

        if (level >= OVERFLOW_LEVEL_CRITICAL && queue->overflow) {
            overflow_handler_write(queue->overflow, entry);
            audit_entry_destroy(entry);

            airy_mtx_lock(&queue->level_lock);
            queue->current_level = level;
            airy_mtx_unlock(&queue->level_lock);

            if (cb) {
                cb(level, audit_queue_size(queue->queue), queue->max_size, cb_user_data);
            }

            return 0;
        } else {
            /* 审计条目不得静默丢失：丢弃路径同样必须销毁条目，
             * 否则内存泄漏且违反审计链完整性。 */
            audit_entry_destroy(entry);
            atomic_fetch_add_64(&queue->total_dropped, 1, memory_order_seq_cst);

            airy_mtx_lock(&queue->level_lock);
            queue->current_level = level;
            airy_mtx_unlock(&queue->level_lock);

            if (cb) {
                cb(level, audit_queue_size(queue->queue), queue->max_size, cb_user_data);
            }

            return cupolas_ERROR_WOULD_BLOCK;
        }
    }

    overflow_level_t level =
        overflow_handler_check_level(audit_queue_size(queue->queue), queue->max_size);

    airy_mtx_lock(&queue->level_lock);
    overflow_level_t prev_level = queue->current_level;
    if (level != prev_level) {
        queue->current_level = level;
        airy_mtx_unlock(&queue->level_lock);

        if (cb && level > prev_level) {
            cb(level, audit_queue_size(queue->queue), queue->max_size, cb_user_data);
        }
    } else {
        airy_mtx_unlock(&queue->level_lock);
    }

    return result;
}

int audit_queue_ex_pop(audit_queue_ex_t *queue, audit_entry_t **entry)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    return audit_queue_pop(queue->queue, entry);
}

int audit_queue_ex_pop_batch(audit_queue_ex_t *queue, audit_entry_t **entries, size_t max_count,
                             size_t *actual_count)
{
    if (!queue || !entries || !actual_count)
        return cupolas_ERROR_INVALID_ARG;

    return audit_queue_pop_batch(queue->queue, entries, max_count, actual_count);
}

void audit_queue_ex_shutdown(audit_queue_ex_t *queue, bool wait_empty)
{
    if (!queue)
        return;

    audit_queue_shutdown(queue->queue, wait_empty);
}

size_t audit_queue_ex_size(audit_queue_ex_t *queue)
{
    if (!queue)
        return 0;

    return audit_queue_size(queue->queue);
}

void audit_queue_ex_get_stats(audit_queue_ex_t *queue, uint64_t *pushed, uint64_t *popped,
                              uint64_t *spilled, uint64_t *dropped)
{
    if (!queue)
        return;

    if (pushed || popped) {
        uint64_t p, pp;
        audit_queue_stats(queue->queue, &p, &pp);
        if (pushed)
            *pushed = p;
        if (popped)
            *popped = pp;
    }

    if (spilled && queue->overflow) {
        overflow_stats_t stats;
        overflow_handler_get_stats(queue->overflow, &stats);
        *spilled = stats.events_written_to_disk;
    } else if (spilled) {
        *spilled = 0;
    }

    if (dropped) {
        *dropped = atomic_load_64(&queue->total_dropped, memory_order_seq_cst);
    }
}

overflow_level_t audit_queue_ex_get_overflow_level(audit_queue_ex_t *queue)
{
    if (!queue)
        return OVERFLOW_LEVEL_NORMAL;

    airy_mtx_lock(&queue->level_lock);
    overflow_level_t level = queue->current_level;
    airy_mtx_unlock(&queue->level_lock);

    return level;
}

int audit_queue_ex_set_overflow_callback(audit_queue_ex_t *queue, overflow_callback_t callback,
                                         void *user_data)
{
    if (!queue)
        AIRY_RET_ERR(AIRY_ERR_NULL_POINTER);

    queue->overflow_callback = callback;
    queue->callback_user_data = user_data;

    return 0;
}
