// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security_filter.c - Network Security: Packet Filter and HTTP Security
 */

/**
 * @file cupolas_network_security_filter.c
 * @brief Network Security - 包过滤与 HTTP 安全域
 *
 * 本文件实现主机/URL 规则匹配、连接与 URL 访问检查，
 * 以及 HTTP 请求校验与安全响应头注入。
 * @author SPHARX Ltd. - Airymax Team
 * @date 2026
 */

#include "cupolas_network_security.h"
#include "cupolas_network_security_internal.h"

#include "../platform/platform.h"
#include <platform.h>
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int cupolas_match_host_pattern(const char *pattern, const char *host)
{
    if (!pattern || !host)
        return 0;

    if (strcmp(pattern, "*") == 0)
        return 1;

    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1;
        size_t host_len = strlen(host);
        size_t suffix_len = strlen(suffix);

        if (host_len >= suffix_len) {
            return strcmp(host + host_len - suffix_len, suffix) == 0;
        }
        return 0;
    }

    return strcmp(pattern, host) == 0;
}

static int cupolas_match_url_pattern(const char *pattern, const char *url)
{
    if (!pattern || !url)
        return 0;

    if (strcmp(pattern, "*") == 0)
        return 1;

    return strstr(url, pattern) != NULL;
}

int cupolas_net_check_access(const char *host, uint16_t port, cupolas_proto_t protocol,
                             const char *direction)
{
    if (!host)
        return 0;

    cupolas_mutex_lock(&g_net_security.lock);

    g_net_security.stats.total_connections++;

    if (g_net_security.manager.http.enforce_https && protocol == CUPOLAS_PROTO_TCP) {
        g_net_security.stats.plaintext_blocked++;
        cupolas_mutex_unlock(&g_net_security.lock);
        return 0;
    }

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        cupolas_net_filter_rule_t *rule = &g_net_security.filter_rules[i].rule;

        if (!g_net_security.filter_rules[i].active || !rule->enabled)
            continue;

        int host_match = cupolas_match_host_pattern(rule->host_pattern, host);
        int port_match = (rule->dst_port_start == 0 && rule->dst_port_end == 0) ||
                         (port >= rule->dst_port_start && port <= rule->dst_port_end);
        int proto_match = rule->protocol == 0 || rule->protocol == protocol;

        if (host_match && port_match && proto_match) {
            switch (rule->action) {
            case CUPOLAS_FW_ALLOW:
                cupolas_mutex_unlock(&g_net_security.lock);
                return 1;
            case CUPOLAS_FW_DENY:
                g_net_security.stats.blocked_connections++;
                cupolas_mutex_unlock(&g_net_security.lock);
                return 0;
            case CUPOLAS_FW_LOG:
            case CUPOLAS_FW_RATE_LIMIT:
                cupolas_mutex_unlock(&g_net_security.lock);
                return 1;
            }
        }
    }

    /* 默认拒绝（fail-closed）：无 allow 规则匹配的流量一律拦截，
     * 防止未配置防火墙规则时全部放行（安全穹顶默认拒绝原则）。 */
    g_net_security.stats.blocked_connections++;
    cupolas_mutex_unlock(&g_net_security.lock);
    return 0;
}

int cupolas_net_check_url(const char *url, const char *method)
{
    if (!url)
        return 0;

    cupolas_mutex_lock(&g_net_security.lock);

    g_net_security.stats.http_requests++;

    if (g_net_security.manager.http.enforce_https) {
        if (strncmp(url, "https://", 8) != 0) {
            g_net_security.stats.plaintext_blocked++;
            cupolas_mutex_unlock(&g_net_security.lock);
            return 0;
        }
        g_net_security.stats.https_requests++;
    }

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        cupolas_net_filter_rule_t *rule = &g_net_security.filter_rules[i].rule;

        if (!g_net_security.filter_rules[i].active || !rule->enabled)
            continue;

        if (rule->url_pattern && cupolas_match_url_pattern(rule->url_pattern, url)) {
            switch (rule->action) {
            case CUPOLAS_FW_ALLOW:
                cupolas_mutex_unlock(&g_net_security.lock);
                return 1;
            case CUPOLAS_FW_DENY:
                g_net_security.stats.blocked_connections++;
                cupolas_mutex_unlock(&g_net_security.lock);
                return 0;
            default:
                cupolas_mutex_unlock(&g_net_security.lock);
                return 1;
            }
        }
    }

    if (g_net_security.manager.http.allowed_methods) {
        int method_allowed = 0;
        for (size_t i = 0; i < g_net_security.manager.http.method_count; i++) {
            if (strcmp(g_net_security.manager.http.allowed_methods[i], method) == 0) {
                method_allowed = 1;
                break;
            }
        }
        if (!method_allowed) {
            cupolas_mutex_unlock(&g_net_security.lock);
            return 0;
        }
    } else {
        /* 未配置方法白名单且无 URL 规则匹配：默认拒绝（fail-closed），
         * 需显式配置 allow 规则（如 url_pattern="*" action=allow）才放行 */
        cupolas_mutex_unlock(&g_net_security.lock);
        return 0;
    }

    cupolas_mutex_unlock(&g_net_security.lock);
    return 1;
}

int cupolas_http_configure(const cupolas_http_security_config_t *manager)
{
    if (!manager)
        return AIRY_ERR_UNKNOWN;
    g_net_security.manager.http.enforce_https = manager->enforce_https;
    g_net_security.manager.http.max_url_length = manager->max_url_length;
    g_net_security.manager.http.max_body_size = manager->max_body_size;
    g_net_security.manager.http.allowed_methods = manager->allowed_methods;
    g_net_security.manager.http.method_count = manager->method_count;
    g_net_security.manager.http.forbidden_headers = manager->forbidden_headers;
    g_net_security.manager.http.forbidden_count = manager->forbidden_count;
    return 0;
}

int cupolas_http_validate_request(const char *method, const char *url, const char **headers,
                                  size_t header_count, size_t body_size)
{
    if (!method || !url)
        return AIRY_ERR_UNKNOWN;

    if (g_net_security.manager.http.max_url_length > 0) {
        if (strlen(url) > g_net_security.manager.http.max_url_length) {
            return AIRY_ERR_UNKNOWN;
        }
    }

    if (g_net_security.manager.http.max_body_size > 0) {
        if (body_size > g_net_security.manager.http.max_body_size) {
            return AIRY_ERR_UNKNOWN;
        }
    }

    if (g_net_security.manager.http.allowed_methods) {
        int method_allowed = 0;
        for (size_t i = 0; i < g_net_security.manager.http.method_count; i++) {
            if (strcmp(g_net_security.manager.http.allowed_methods[i], method) == 0) {
                method_allowed = 1;
                break;
            }
        }
        if (!method_allowed)
            return AIRY_ERR_UNKNOWN;
    }

    if (g_net_security.manager.http.forbidden_headers && headers) {
        for (size_t i = 0; i < header_count; i++) {
            for (size_t j = 0; j < g_net_security.manager.http.forbidden_count; j++) {
                if (strncmp(headers[i], g_net_security.manager.http.forbidden_headers[j],
                            strlen(g_net_security.manager.http.forbidden_headers[j])) == 0) {
                    return AIRY_ERR_UNKNOWN;
                }
            }
        }
    }

    return 0;
}

int cupolas_http_add_security_headers(const char **headers, size_t header_count, size_t max_headers)
{
    if (!headers)
        return AIRY_ERR_UNKNOWN;

    static const char *security_headers[] = {
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "X-Content-Type-Options: nosniff", "X-Frame-Options: DENY",
        "X-XSS-Protection: 1; mode=block", "Content-Security-Policy: default-src 'self'"};

    size_t num_sec_headers = sizeof(security_headers) / sizeof(security_headers[0]);
    size_t total = header_count + num_sec_headers;

    if (total > max_headers) {
        return AIRY_ERR_UNKNOWN;
    }

    for (size_t i = 0; i < num_sec_headers; i++) {
        ((char **)headers)[header_count + i] = cupolas_strdup(security_headers[i]);
    }

    return 0;
}

int cupolas_http_is_url_safe(const char *url)
{
    if (!url)
        return 0;

    const char *dangerous_patterns[] = {"..",  "//",          "\\",    "%00",      "%0a",
                                        "%0d", "javascript:", "data:", "vbscript:"};

    for (size_t i = 0; i < sizeof(dangerous_patterns) / sizeof(dangerous_patterns[0]); i++) {
        if (strstr(url, dangerous_patterns[i]) != NULL) {
            return 0;
        }
    }

    return 1;
}
