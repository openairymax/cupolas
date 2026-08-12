// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security_conn.c - Network Security: Connection Monitoring Implementation
 */

/**
 * @file cupolas_network_security_conn.c
 * @brief Network Security - 连接监控域
 *
 * 本文件实现连接信息枚举、连接关闭与统计信息查询/重置。
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

int cupolas_net_get_connections(cupolas_connection_info_t **connections, size_t *count)
{
    if (!connections || !count)
        return AIRY_ERR_UNKNOWN;

    *count = g_net_security.connection_count;
    SAFE_MALLOC_ARRAY(*connections, *count, sizeof(cupolas_connection_info_t));
    if (!*connections)
        return AIRY_ERR_UNKNOWN;

    for (size_t i = 0; i < *count; i++) {
        (*connections)[i] = g_net_security.connections[i];
    }

    return 0;
}

int cupolas_net_close_connection(const char *local_ip, uint16_t local_port, const char *remote_ip,
                                 uint16_t remote_port)
{
    if (!local_ip || !remote_ip)
        return AIRY_ERR_UNKNOWN;

    for (size_t i = 0; i < g_net_security.connection_count; i++) {
        cupolas_connection_info_t *conn = &g_net_security.connections[i];

        if (conn->local_port == local_port && conn->remote_port == remote_port &&
            strcmp(conn->local_ip, local_ip) == 0 && strcmp(conn->remote_ip, remote_ip) == 0) {
            cupolas_free_connection_info(conn);

            for (size_t j = i; j < g_net_security.connection_count - 1; j++) {
                g_net_security.connections[j] = g_net_security.connections[j + 1];
            }
            g_net_security.connection_count--;
            g_net_security.stats.active_connections--;
            return 0;
        }
    }

    return AIRY_ERR_UNKNOWN;
}

int cupolas_net_get_stats(cupolas_net_stats_t *stats)
{
    if (!stats)
        return AIRY_ERR_UNKNOWN;
    *stats = g_net_security.stats;
    return 0;
}

void cupolas_net_reset_stats(void)
{
    __builtin_memset(&g_net_security.stats, 0, sizeof(g_net_security.stats));
}
