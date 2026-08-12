// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security_firewall.c - Network Security: Firewall Rules Implementation
 */

/**
 * @file cupolas_network_security_firewall.c
 * @brief Network security: firewall rules management domain.
 *
 * Implements add/delete/update/query/list management of filter rules.
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

int cupolas_net_add_rule(const cupolas_net_filter_rule_t *rule)
{
    if (!rule)
        return AIRY_ERR_UNKNOWN;

    cupolas_mutex_lock(&g_net_security.lock);
    if (g_net_security.filter_rule_count >= cupolas_MAX_FILTER_RULES) {
        cupolas_mutex_unlock(&g_net_security.lock);
        return AIRY_ERR_UNKNOWN;
    }

    filter_rule_entry_t *entry = &g_net_security.filter_rules[g_net_security.filter_rule_count];
    __builtin_memset(entry, 0, sizeof(*entry));

    entry->rule.rule_id = cupolas_strdup(rule->rule_id);
    entry->rule.description = cupolas_strdup(rule->description);
    entry->rule.src_ip_pattern = cupolas_strdup(rule->src_ip_pattern);
    entry->rule.dst_ip_pattern = cupolas_strdup(rule->dst_ip_pattern);
    entry->rule.src_port_start = rule->src_port_start;
    entry->rule.src_port_end = rule->src_port_end;
    entry->rule.dst_port_start = rule->dst_port_start;
    entry->rule.dst_port_end = rule->dst_port_end;
    entry->rule.protocol = rule->protocol;
    entry->rule.host_pattern = cupolas_strdup(rule->host_pattern);
    entry->rule.url_pattern = cupolas_strdup(rule->url_pattern);
    entry->rule.action = rule->action;
    entry->rule.priority = rule->priority;
    entry->rule.enabled = rule->enabled;
    entry->rule.rate_limit = rule->rate_limit;
    entry->rule.burst_limit = rule->burst_limit;
    entry->active = 1;

    g_net_security.filter_rule_count++;
    cupolas_mutex_unlock(&g_net_security.lock);
    return 0;
}

int cupolas_net_remove_rule(const char *rule_id)
{
    if (!rule_id)
        return AIRY_ERR_UNKNOWN;

    cupolas_mutex_lock(&g_net_security.lock);

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        if (g_net_security.filter_rules[i].rule.rule_id &&
            strcmp(g_net_security.filter_rules[i].rule.rule_id, rule_id) == 0) {
            cupolas_free_filter_rule(&g_net_security.filter_rules[i].rule);

            for (size_t j = i; j < g_net_security.filter_rule_count - 1; j++) {
                g_net_security.filter_rules[j] = g_net_security.filter_rules[j + 1];
            }
            g_net_security.filter_rule_count--;
            cupolas_mutex_unlock(&g_net_security.lock);
            return 0;
        }
    }

    cupolas_mutex_unlock(&g_net_security.lock);
    return AIRY_ERR_UNKNOWN;
}

int cupolas_net_update_rule(const char *rule_id, const cupolas_net_filter_rule_t *rule)
{
    if (!rule_id || !rule)
        return AIRY_ERR_UNKNOWN;

    cupolas_mutex_lock(&g_net_security.lock);

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        if (g_net_security.filter_rules[i].rule.rule_id &&
            strcmp(g_net_security.filter_rules[i].rule.rule_id, rule_id) == 0) {
            cupolas_free_filter_rule(&g_net_security.filter_rules[i].rule);

            g_net_security.filter_rules[i].rule.rule_id = cupolas_strdup(rule->rule_id);
            g_net_security.filter_rules[i].rule.description = cupolas_strdup(rule->description);
            g_net_security.filter_rules[i].rule.src_ip_pattern =
                cupolas_strdup(rule->src_ip_pattern);
            g_net_security.filter_rules[i].rule.dst_ip_pattern =
                cupolas_strdup(rule->dst_ip_pattern);
            g_net_security.filter_rules[i].rule.src_port_start = rule->src_port_start;
            g_net_security.filter_rules[i].rule.src_port_end = rule->src_port_end;
            g_net_security.filter_rules[i].rule.dst_port_start = rule->dst_port_start;
            g_net_security.filter_rules[i].rule.dst_port_end = rule->dst_port_end;
            g_net_security.filter_rules[i].rule.protocol = rule->protocol;
            g_net_security.filter_rules[i].rule.host_pattern = cupolas_strdup(rule->host_pattern);
            g_net_security.filter_rules[i].rule.url_pattern = cupolas_strdup(rule->url_pattern);
            g_net_security.filter_rules[i].rule.action = rule->action;
            g_net_security.filter_rules[i].rule.priority = rule->priority;
            g_net_security.filter_rules[i].rule.enabled = rule->enabled;
            g_net_security.filter_rules[i].rule.rate_limit = rule->rate_limit;
            g_net_security.filter_rules[i].rule.burst_limit = rule->burst_limit;

            cupolas_mutex_unlock(&g_net_security.lock);
            return 0;
        }
    }

    cupolas_mutex_unlock(&g_net_security.lock);
    return AIRY_ERR_UNKNOWN;
}

int cupolas_net_get_rule(const char *rule_id, cupolas_net_filter_rule_t *rule)
{
    if (!rule_id || !rule)
        return AIRY_ERR_UNKNOWN;

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        if (g_net_security.filter_rules[i].rule.rule_id &&
            strcmp(g_net_security.filter_rules[i].rule.rule_id, rule_id) == 0) {
            *rule = g_net_security.filter_rules[i].rule;
            return 0;
        }
    }

    return AIRY_ERR_UNKNOWN;
}

int cupolas_net_list_rules(cupolas_net_filter_rule_t **rules, size_t *count)
{
    if (!rules || !count)
        return AIRY_ERR_UNKNOWN;

    *count = g_net_security.filter_rule_count;
    SAFE_MALLOC_ARRAY(*rules, *count, sizeof(cupolas_net_filter_rule_t));
    if (!*rules)
        return AIRY_ERR_UNKNOWN;

    for (size_t i = 0; i < *count; i++) {
        (*rules)[i] = g_net_security.filter_rules[i].rule;
    }

    return 0;
}
