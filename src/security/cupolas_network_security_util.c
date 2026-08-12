// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security_util.c - Network Security: Address and URL Utilities
 */

/**
 * @file cupolas_network_security_util.c
 * @brief Network Security - 网络工具域
 *
 * 本文件实现 URL 解析、CIDR 归属判定与 IP/端口合法性校验。
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

int cupolas_net_parse_url(const char *url, char *scheme, char *host, uint16_t *port, char *path)
{
    if (!url)
        return AIRY_ERR_UNKNOWN;

    const char *p = url;

    const char *colon = strstr(p, "://");
    if (colon && scheme) {
        size_t scheme_len = colon - p;
        AIRY_STRNCPY_TERM(scheme, p, scheme_len);
        p = colon + 3;
    }

    const char *slash = strchr(p, '/');
    const char *port_colon = strchr(p, ':');

    if (host) {
        size_t host_len;
        if (port_colon && (!slash || port_colon < slash)) {
            host_len = port_colon - p;
        } else if (slash) {
            host_len = slash - p;
        } else {
            host_len = strlen(p);
        }
        size_t copy_len = host_len < (size_t)255 ? host_len : 255;
        __builtin_memcpy(host, p, copy_len);
        host[copy_len] = '\0';
    }

    if (port_colon && (!slash || port_colon < slash)) {
        if (port) {
            *port = (uint16_t)strtol(port_colon + 1, NULL, 10);
        }
        p = port_colon + 1;
        while (*p && *p != '/')
            p++;
    } else {
        if (port) {
            if (scheme && strcmp(scheme, "https") == 0) {
                *port = 443;
            } else if (scheme && strcmp(scheme, "http") == 0) {
                *port = 80;
            } else {
                *port = 0;
            }
        }
    }

    if (path) {
        if (slash) {
            snprintf(path, 256, "%s", slash);
        } else {
            snprintf(path, 256, "%s", "/");
        }
    }

    return 0;
}

int cupolas_net_ip_in_cidr(const char *ip, const char *cidr)
{
    if (!ip || !cidr)
        return 0;

    char cidr_copy[64];
    AIRY_STRNCPY_TERM(cidr_copy, cidr, sizeof(cidr_copy));

    char *slash = strchr(cidr_copy, '/');
    if (!slash)
        return strcmp(ip, cidr_copy) == 0 ? 1 : 0;

    *slash = '\0';
    int prefix_len = (int)strtol(slash + 1, NULL, 10);

    struct in_addr ip_addr, cidr_addr;
    if (inet_pton(AF_INET, ip, &ip_addr) != 1)
        return 0;
    if (inet_pton(AF_INET, cidr_copy, &cidr_addr) != 1)
        return 0;

    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    uint32_t ip_net = ntohl(ip_addr.s_addr) & mask;
    uint32_t cidr_net = ntohl(cidr_addr.s_addr) & mask;

    return ip_net == cidr_net ? 1 : 0;
}

int cupolas_net_validate_ip(const char *ip)
{
    if (!ip)
        return 0;

    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1 ? 1 : 0;
}

int cupolas_net_validate_port(uint16_t port)
{
    return (port >= 1) ? 1 : 0;
}
