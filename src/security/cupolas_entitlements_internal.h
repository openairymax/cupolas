/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * cupolas_entitlements_internal.h - 内部共享头（entitlements 三模块域）
 *
 * 公共头 cupolas_entitlements.h 保持不透明（struct cupolas_entitlements
 * 仅在此处补全），供 core/parse/crypto 三个实现文件共享结构体与跨模块
 * 内部接口，避免在公共 API 中暴露实现细节。
 */

#ifndef CUPOLAS_ENTITLEMENTS_INTERNAL_H
#define CUPOLAS_ENTITLEMENTS_INTERNAL_H

#include "cupolas_entitlements.h"

#include "../platform/platform.h"
#include "atomic_compat.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 完整结构定义（公共头保持不透明） */
struct cupolas_entitlements {
    cupolas_entitlements_info_t info;
    char *raw_content;
    char *signature;
    size_t sig_len;
    uint64_t load_time;
    int is_verified;
    cupolas_mutex_t lock;
};

/* parse 模块（cupolas_entitlements_parse.c） */
void cupolas_free_string_array(char **arr, size_t count);
int cupolas_parse_entitlements_content(const char *content, cupolas_entitlements_info_t *info);

/* crypto 模块（cupolas_entitlements_crypto.c）：fail-closed 预仲裁检查
 * （签名已校验且处于有效期内，否则一律拒绝）。 */
int entitlements_verified_valid(cupolas_entitlements_t *entitlements);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_ENTITLEMENTS_INTERNAL_H */
