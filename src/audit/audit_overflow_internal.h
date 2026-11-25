/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * audit_overflow_internal.h - 溢出处理器内部契约：状态与落盘域接口
 */

#ifndef CUPOLAS_AUDIT_OVERFLOW_INTERNAL_H
#define CUPOLAS_AUDIT_OVERFLOW_INTERNAL_H

#include "audit_overflow.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define OVERFLOW_DIR_MAX 512
#define OVERFLOW_NAME_MAX 256
#define OVERFLOW_JSON_MAX 2048
#define OVERFLOW_SCAN_MAX 512
/* 保留份数与 A-3 审计 500MB 上限对齐：默认件 100MB × 5。 */
#define OVERFLOW_KEEP_FILES 5
#define OVERFLOW_KEEP_MAX 1024
#define DEFAULT_MAX_FILE_SIZE_MB 100
#define DEFAULT_FLUSH_INTERVAL_MS 1000

struct overflow_handler {
    char overflow_dir[OVERFLOW_DIR_MAX];
    size_t max_file_size_bytes;
    uint32_t flush_interval_ms;
    FILE *current_file;
    char current_filename[OVERFLOW_NAME_MAX];
    uint64_t current_file_size;
    uint64_t events_written;
    uint64_t disk_write_errors;
    uint64_t total_events_received;
    airy_mtx_t lock;
    airy_thread_t flush_thread;
    volatile bool running;
    overflow_callback_t callback;
    void *callback_user_data;
    overflow_stats_t stats;
    int keep_files;
};

int ovf_ensure_dir(const char *dir);
int ovf_open_new(overflow_handler_t *handler);
int ovf_write_entry(FILE *file, audit_entry_t *entry);
void ovf_reclaim(overflow_handler_t *handler, int keep, const char *skip);

#endif /* CUPOLAS_AUDIT_OVERFLOW_INTERNAL_H */
