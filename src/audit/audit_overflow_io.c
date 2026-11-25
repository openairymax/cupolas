// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file audit_overflow_io.c
 * @brief 溢出落盘域：文件命名、目录准备、条目序列化与打开
 *
 * 只承担落盘机制；队列背压分级与回调见 audit_overflow.c。
 */

#include "audit_overflow_internal.h"

#include "airy_memory.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "error.h"

static void ovf_name(char *buffer, size_t buffer_size)
{
    time_t now = time(NULL);
#if AIRY_PLATFORM_WINDOWS
    struct tm *tm_info = localtime(&now);
#else
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
#endif
    if (tm_info) {
        strftime(buffer, buffer_size, "audit_overflow_%Y%m%d_%H%M%S.log", tm_info);
    } else {
        snprintf(buffer, buffer_size, "audit_overflow_unknown.log");
    }
}

/* 备份名唯一化：时间戳精确到秒，同一秒内轮转/重启会撞名；
 * 撞名即追加到旧文件，既污染上一份内容又重置计数（旧缺陷）。
 * 依次尝试 base、base 的 stem 加 _1.._999 序号，取首个不存在的名字。 */
static int ovf_unique(char *out, size_t out_size, const char *dir)
{
    char base[OVERFLOW_NAME_MAX];
    ovf_name(base, sizeof(base));

    char stem[OVERFLOW_NAME_MAX];
    char ext[16] = ".log";
    const char *dot = strrchr(base, '.');
    if (dot && strlen(dot) < sizeof(ext)) {
        snprintf(ext, sizeof(ext), "%s", dot);
        size_t n = (size_t)(dot - base);
        if (n >= sizeof(stem))
            n = sizeof(stem) - 1;
        snprintf(stem, sizeof(stem), "%.*s", (int)n, base);
    } else {
        snprintf(stem, sizeof(stem), "%s", base);
        ext[0] = '\0';
    }

    char path[768];
    if (snprintf(path, sizeof(path), "%s/%s", dir, base) < (int)sizeof(path) &&
        !airy_file_exists(path)) {
        snprintf(out, out_size, "%s", base);
        return 0;
    }
    for (int seq = 1; seq < 1000; seq++) {
        snprintf(base, sizeof(base), "%s_%d%s", stem, seq, ext);
        if (snprintf(path, sizeof(path), "%s/%s", dir, base) >= (int)sizeof(path))
            continue;
        if (!airy_file_exists(path)) {
            snprintf(out, out_size, "%s", base);
            return 0;
        }
    }
    return -1;
}

int ovf_ensure_dir(const char *dir)
{
    if (!dir)
        AIRY_RET_ERR(AIRY_ERR_NULL_POINTER);

    /* 目录创建收敛至 airy_mkdir_p 递归通道（audit_rotator 同范式）。
     * 历史单级 mkdir：父级缺失即 ENOENT，回退路径同样单级且忽略返回值，
     * fopen 失败致 overflow_handler_create 返回 NULL——windows run
     * 36393198095 audit_overflow_tests 首轮 0xc0000409 即此形态，
     * 恰因同批测试套件先补建了 tmp 根目录才在重跑时通过。
     * 已存在属成功语义（同名非目录由后续 fopen 失败兜底）。 */
    if (airy_mkdir_p(dir) == 0)
        return 0;

    return airy_file_exists(dir) ? 0 : -1;
}

int ovf_open_new(overflow_handler_t *handler)
{
    if (handler->current_file) {
        fclose(handler->current_file);
        handler->current_file = NULL;
    }

    /* 每次打开都生成新名字：旧实现沿用 create 时算好的名字，越过
     * max_file_size 后重开同一文件并把计数清零，导致单文件无限增长。 */
    if (ovf_unique(handler->current_filename, sizeof(handler->current_filename),
                   handler->overflow_dir) != 0) {
        handler->disk_write_errors++;
        return -1;
    }

    char filepath[768];
    snprintf(filepath, sizeof(filepath), "%s/%s", handler->overflow_dir, handler->current_filename);

    handler->current_file = fopen(filepath, "a");
    if (!handler->current_file) {
        handler->disk_write_errors++;
        return -1;
    }

    handler->current_file_size = 0;
    handler->events_written = 0;

    return 0;
}

static void ovf_escape(const char *src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size == 0) {
        if (dst && dst_size > 0)
            *dst = '\0';
        return;
    }

    size_t pos = 0;
    while (*src && pos < dst_size - 2) {
        switch (*src) {
        case '"':
            if (pos + 2 >= dst_size - 1)
                goto done;
            dst[pos++] = '\\';
            dst[pos++] = '"';
            break;
        case '\\':
            if (pos + 2 >= dst_size - 1)
                goto done;
            dst[pos++] = '\\';
            dst[pos++] = '\\';
            break;
        case '\n':
            if (pos + 2 >= dst_size - 1)
                goto done;
            dst[pos++] = '\\';
            dst[pos++] = 'n';
            break;
        case '\r':
            if (pos + 2 >= dst_size - 1)
                goto done;
            dst[pos++] = '\\';
            dst[pos++] = 'r';
            break;
        case '\t':
            if (pos + 2 >= dst_size - 1)
                goto done;
            dst[pos++] = '\\';
            dst[pos++] = 't';
            break;
        default:
            if ((unsigned char)*src < 0x20) {
                if (pos + 4 >= dst_size - 1)
                    goto done;
                pos += snprintf(dst + pos, dst_size - pos, "\\u%04x", (unsigned char)*src);
            } else {
                dst[pos++] = *src;
            }
            break;
        }
        src++;
    }
done:
    dst[pos] = '\0';
}

int ovf_write_entry(FILE *file, audit_entry_t *entry)
{
    if (!file || !entry)
        AIRY_RET_ERR(AIRY_ERR_NULL_POINTER);

    char agent_escaped[256], action_escaped[256], resource_escaped[256], detail_escaped[512];

    ovf_escape(entry->agent_id ? entry->agent_id : "", agent_escaped, sizeof(agent_escaped));
    ovf_escape(entry->action ? entry->action : "", action_escaped, sizeof(action_escaped));
    ovf_escape(entry->resource ? entry->resource : "", resource_escaped, sizeof(resource_escaped));
    ovf_escape(entry->detail ? entry->detail : "", detail_escaped, sizeof(detail_escaped));

    char json_buffer[OVERFLOW_JSON_MAX];
    int len = snprintf(json_buffer, sizeof(json_buffer),
                       "{\"ts\":%llu,\"type\":%d,\"agent\":\"%s\",\"action\":\"%s\",\"resource\":"
                       "\"%s\",\"detail\":\"%s\",\"result\":%d}\n",
                       (unsigned long long)entry->timestamp_ms, entry->type, agent_escaped,
                       action_escaped, resource_escaped, detail_escaped, entry->result);

    if (len < 0 || (size_t)len >= sizeof(json_buffer)) {
        AIRY_RET_ERR(AIRY_ERR_BUFFER_TOO_SMALL);
    }

    if (fwrite(json_buffer, 1, len, file) != (size_t)len) {
        AIRY_RET_ERR(AIRY_ERR_IO);
    }

    return len;
}
