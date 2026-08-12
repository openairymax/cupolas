// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security_dns.c - Network Security: DNS Security Implementation
 */

/**
 * @file cupolas_network_security_dns.c
 * @brief Network security: DNS security domain.
 *
 * Implements DNS security configuration, resolution interception,
 * domain whitelist/blacklist, and DNSSEC validation.
 */

#include "cupolas_network_security.h"
#include "cupolas_network_security_internal.h"

#include <ctype.h>

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

int cupolas_dns_configure(const cupolas_dns_security_config_t *manager)
{
    if (!manager)
        return AIRY_ERR_UNKNOWN;
    g_net_security.manager.dns.enable_dnssec = manager->enable_dnssec;
    AIRY_STRNCPY_TERM(g_net_security.manager.dns.upstream_server, manager->upstream_server,
                      sizeof(g_net_security.manager.dns.upstream_server));
    return 0;
}

int cupolas_dns_resolve(const char *hostname, char *ip_out, size_t ip_len)
{
    if (!hostname || !ip_out || ip_len == 0)
        return AIRY_ERR_UNKNOWN;

    g_net_security.stats.dns_queries++;

    if (g_net_security.manager.dns.blocked_domains) {
        for (size_t i = 0; i < g_net_security.manager.dns.blocked_count; i++) {
            if (strstr(hostname, g_net_security.manager.dns.blocked_domains[i]) != NULL) {
                g_net_security.stats.dns_blocked++;
                return AIRY_ERR_UNKNOWN;
            }
        }
    }

    struct hostent *host = gethostbyname(hostname);
    if (!host)
        return AIRY_ERR_UNKNOWN;

    const char *ip = inet_ntoa(*(struct in_addr *)host->h_addr);
    if (!ip)
        return AIRY_ERR_UNKNOWN;

    AIRY_STRNCPY_TERM(ip_out, ip, ip_len);

    return 0;
}

int cupolas_dns_is_domain_allowed(const char *domain)
{
    if (!domain)
        return 0;

    if (g_net_security.manager.dns.blocked_domains) {
        for (size_t i = 0; i < g_net_security.manager.dns.blocked_count; i++) {
            if (strstr(domain, g_net_security.manager.dns.blocked_domains[i]) != NULL) {
                return 0;
            }
        }
    }

    if (g_net_security.manager.dns.allowed_domains && g_net_security.manager.dns.domain_count > 0) {
        for (size_t i = 0; i < g_net_security.manager.dns.domain_count; i++) {
            if (strcmp(domain, g_net_security.manager.dns.allowed_domains[i]) == 0) {
                return 1;
            }
        }
        return 0;
    }

    return 1;
}

int cupolas_dns_verify_dnssec(const char *domain)
{
    if (!domain)
        return 0;

    if (!g_net_security.manager.dns.enable_dnssec)
        return 0;

#ifdef __linux__

    const char *p = domain;
    int valid = 1;
    while (*p) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '.' && *p != '_') {
            valid = 0;
            break;
        }
        p++;
    }
    if (!valid)
        return 0;

    /* BAN-211/235: execvp dig directly (no shell) to eliminate command
     * injection risk. domain passed the whitelist check above, so it only
     * contains alnum/-/./_. */
    const char *const argv[] = {"dig", "+dnssec", "+short", domain, "DNSKEY", NULL};
    char output[4096];
    int exit_code =
        airy_process_run_capture("dig", (char *const *)argv, NULL, 5000, output, sizeof(output));
    if (exit_code == 0 && (strstr(output, "DNSKEY") || strstr(output, "RRSIG"))) {
        return 1;
    }
    return 0;
#else
    return 0;
#endif
}
