// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_network_security_filter.c - Network Security: Packet Filter and HTTP Security
 */

/**
 * @file cupolas_network_security_filter.c
 * @brief Network security: packet filter and HTTP security domain.
 *
 * Implements host/URL rule matching, connection and URL access checks,
 * HTTP request validation, and secure response-header injection.
 */

#include "airy_memory.h"
#include "cupolas_network_security_internal.h"

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

    airy_mtx_lock(&g_net_security.lock);

    g_net_security.stats.total_connections++;

    if (g_net_security.manager.http.enforce_https && protocol == CUPOLAS_PROTO_TCP) {
        g_net_security.stats.plaintext_blocked++;
        airy_mtx_unlock(&g_net_security.lock);
        return 0;
    }

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        cupolas_net_filter_rule_t *rule = &g_net_security.filter_rules[i].rule;

        if (!g_net_security.filter_rules[i].active || !rule->enabled)
            continue;

        int host_match = cupolas_host_match(rule->host_pattern, host);
        int port_match = (rule->dst_port_start == 0 && rule->dst_port_end == 0) ||
                         (port >= rule->dst_port_start && port <= rule->dst_port_end);
        int proto_match = rule->protocol == 0 || rule->protocol == protocol;

        if (host_match && port_match && proto_match) {
            switch (rule->action) {
            case CUPOLAS_FW_ALLOW:
                airy_mtx_unlock(&g_net_security.lock);
                return 1;
            case CUPOLAS_FW_DENY:
                g_net_security.stats.blocked_connections++;
                airy_mtx_unlock(&g_net_security.lock);
                return 0;
            case CUPOLAS_FW_LOG:
            case CUPOLAS_FW_RATE_LIMIT:
                airy_mtx_unlock(&g_net_security.lock);
                return 1;
            }
        }
    }

    /* Deny by default (fail-closed): traffic not matching any allow rule is
     * intercepted, preventing all traffic from passing when no firewall
     * rules are configured (security dome default-deny principle). */
    g_net_security.stats.blocked_connections++;
    airy_mtx_unlock(&g_net_security.lock);
    return 0;
}

/* Method whitelist gate shared by the URL gate and request validation.
 * With no whitelist configured the URL gate fails closed (fail_open=0)
 * while request validation lets the request pass (fail_open=1). */
static int http_method_allowed(const char *method, int fail_open)
{
    if (!g_net_security.manager.http.allowed_methods)
        return fail_open;

    for (size_t i = 0; i < g_net_security.manager.http.method_count; i++) {
        if (strcmp(g_net_security.manager.http.allowed_methods[i], method) == 0)
            return 1;
    }
    return 0;
}

int cupolas_net_check_url(const char *url, const char *method)
{
    if (!url)
        return 0;

    airy_mtx_lock(&g_net_security.lock);

    g_net_security.stats.http_requests++;

    if (g_net_security.manager.http.enforce_https) {
        if (strncmp(url, "https://", 8) != 0) {
            g_net_security.stats.plaintext_blocked++;
            airy_mtx_unlock(&g_net_security.lock);
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
                airy_mtx_unlock(&g_net_security.lock);
                return 1;
            case CUPOLAS_FW_DENY:
                g_net_security.stats.blocked_connections++;
                airy_mtx_unlock(&g_net_security.lock);
                return 0;
            default:
                airy_mtx_unlock(&g_net_security.lock);
                return 1;
            }
        }
    }

    if (!http_method_allowed(method, 0)) {
        airy_mtx_unlock(&g_net_security.lock);
        return 0;
    }

    airy_mtx_unlock(&g_net_security.lock);
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

    if (!http_method_allowed(method, 1))
        return AIRY_ERR_UNKNOWN;

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
        ((char **)headers)[header_count + i] = AIRY_STRDUP(security_headers[i]);
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
