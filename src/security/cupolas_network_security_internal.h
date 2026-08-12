// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_network_security_internal.h
 * @brief 网络安全模块内部共享定义：全局状态结构体、规则条目与跨文件辅助函数声明
 */

#ifndef AIRY_CUPOLAS_NETWORK_SECURITY_INTERNAL_H
#define AIRY_CUPOLAS_NETWORK_SECURITY_INTERNAL_H

#include "cupolas.h"
#include "cupolas_network_security.h"

#include "../platform/platform.h"
#include <platform.h>
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include <stddef.h>
#include <stdint.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define cupolas_MAX_FILTER_RULES 512
#define cupolas_MAX_CONNECTIONS 1024
#define cupolas_MAX_URL_LEN 2048

typedef struct {
    cupolas_net_filter_rule_t rule;
    int active;
} filter_rule_entry_t;

typedef struct {
    int initialized;
    cupolas_tls_config_t manager;

    filter_rule_entry_t filter_rules[cupolas_MAX_FILTER_RULES];
    size_t filter_rule_count;

    cupolas_connection_info_t connections[cupolas_MAX_CONNECTIONS];
    size_t connection_count;

    cupolas_net_stats_t stats;

    SSL_CTX *ssl_ctx;

    void (*ids_callback)(const char *alert_type, const char *details,
                         const cupolas_connection_info_t *conn);

    cupolas_mutex_t lock;
} cupolas_net_security_state_t;

extern cupolas_net_security_state_t g_net_security;

void cupolas_free_filter_rule(cupolas_net_filter_rule_t *rule);

void cupolas_free_connection_info(cupolas_connection_info_t *info);

#endif /* AIRY_CUPOLAS_NETWORK_SECURITY_INTERNAL_H */
