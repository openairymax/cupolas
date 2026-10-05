// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * permission_rule.c - Permission Rule Manager Implementation
 */

/**
 * @file permission_rule.c
 * @brief Permission Rule Manager Implementation
 * @author SPHARX Ltd. - Airymax Team
 */

#include "platform.h"
#include "atomic_compat.h"
#include "airy_memory.h"
#include "permission_rule.h"
#include "security/cupolas_error.h"

#include "yaml_minimal.h" /* SP03: migrated to commons/utils/config_unified/ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 4096
#define DEFAULT_PRIORITY 100

static void cupolas_permission_free_rule(permission_rule_t *rule)
{
    if (!rule)
        return;
    AIRY_FREE(rule->agent_id);
    AIRY_FREE(rule->action);
    AIRY_FREE(rule->resource);
    AIRY_FREE(rule->resource_pattern);
    AIRY_FREE(rule);
}

static void cupolas_permission_free_rules(permission_rule_t *rules)
{
    while (rules) {
        permission_rule_t *next = rules->next;
        cupolas_permission_free_rule(rules);
        rules = next;
    }
}

static permission_rule_t *cupolas_permission_create_rule(const char *agent_id, const char *action,
                                                         const char *resource, int allow,
                                                         int priority)
{
    permission_rule_t *rule = (permission_rule_t *)AIRY_CALLOC(1, sizeof(permission_rule_t));
    if (!rule)
        return NULL;

    __builtin_memset(rule, 0, sizeof(permission_rule_t));

    if (agent_id) {
        rule->agent_id = AIRY_STRDUP(agent_id);
        if (!rule->agent_id)
            goto error;
    }
    if (action) {
        rule->action = AIRY_STRDUP(action);
        if (!rule->action)
            goto error;
    }
    if (resource) {
        rule->resource = AIRY_STRDUP(resource);
        if (!rule->resource)
            goto error;
    }

    rule->allow = allow;
    rule->priority = priority;
    rule->next = NULL;

    return rule;

error:
    cupolas_permission_free_rule(rule);
    return NULL;
}

/*
 * Schema alias: the shipped permission_rules.yaml uses the ACL-style keys
 * {agent, tool, effect} because it is shared with the daemon_security loader
 * (daemons/common/src/security/daemon_security_acl.c). This PDP loader
 * natively reads {agent, action, resource, allow}. Without the alias,
 * "resource" falls back to "*" and "allow" to false, silently turning every
 * rule into a fail-closed deny (R-6). Resolve tool->resource and
 * effect->allow so both consumers agree on the same file.
 */
static const char *cupolas_permission_rule_resource(struct yaml_node *entry)
{
    struct yaml_node *node = yaml_get(entry, "resource");
    if (!node)
        node = yaml_get(entry, "tool");
    return yaml_as_string(node, "*");
}

static int cupolas_permission_rule_allow(struct yaml_node *entry, int default_allow)
{
    struct yaml_node *node = yaml_get(entry, "allow");
    if (node)
        return (int)yaml_as_bool(node, default_allow != 0);

    const char *effect = yaml_as_string(yaml_get(entry, "effect"), NULL);
    if (effect)
        return strcmp(effect, "allow") == 0 ? 1 : 0;

    return default_allow;
}

static int cupolas_permission_match_pattern(const char *pattern, const char *str)
{
    if (!pattern || !str)
        return 0;
    if (strcmp(pattern, "*") == 0)
        return 1;

    const char *p = pattern;
    const char *s = str;
    const char *star = NULL;
    const char *ss = s;

    while (*s) {
        if (*p == '*') {
            star = p++;
            ss = s;
        } else if (*p == *s || *p == '?') {
            p++;
            s++;
        } else if (star) {
            p = star + 1;
            s = ++ss;
        } else {
            return 0;
        }
    }

    while (*p == '*') {
        p++;
    }

    return *p == '\0';
}

rule_manager_t *rule_manager_create(const char *path)
{
    rule_manager_t *mgr = (rule_manager_t *)AIRY_CALLOC(1, sizeof(rule_manager_t));
    if (!mgr)
        return NULL;

    __builtin_memset(mgr, 0, sizeof(rule_manager_t));

    if (airy_rwlock_init(&mgr->rwlock) != cupolas_OK) {
        AIRY_FREE(mgr);
        return NULL;
    }

    if (path) {
        mgr->path = AIRY_STRDUP(path);
        if (!mgr->path) {
            airy_rwlock_destroy(&mgr->rwlock);
            AIRY_FREE(mgr);
            return NULL;
        }

        if (rule_manager_reload(mgr) != 0) {
            AIRY_FREE(mgr->path);
            mgr->path = NULL;
        }
    }

    return mgr;
}

void rule_manager_destroy(rule_manager_t *mgr)
{
    if (!mgr)
        return;

    airy_rwlock_wrlock(&mgr->rwlock);
    cupolas_permission_free_rules(mgr->rules);
    mgr->rules = NULL;
    airy_rwlock_unlock(&mgr->rwlock);

    airy_rwlock_destroy(&mgr->rwlock);
    AIRY_FREE(mgr->path);
    AIRY_FREE(mgr);
}

int rule_manager_reload(rule_manager_t *mgr)
{
    if (!mgr || !mgr->path)
        return cupolas_ERROR_INVALID_ARG;

    airy_file_stat_t st;
    if (airy_file_stat(mgr->path, &st) != 0) {
        return cupolas_ERROR_NOT_FOUND;
    }

    uint64_t mtime = (uint64_t)st.mtime_sec * 1000 + st.mtime_nsec / 1000000;
    if (mtime == mgr->last_mtime) {
        return cupolas_OK;
    }

    yaml_document_t *doc = yaml_create();
    if (!doc)
        return cupolas_ERROR_NO_MEMORY;

    if (yaml_parse_file(doc, mgr->path) != 0) {
        yaml_destroy(doc);
        return cupolas_ERROR_IO;
    }

    permission_rule_t *new_rules = NULL;
    permission_rule_t **tail = &new_rules;

    struct yaml_node *root = yaml_root(doc);
    if (root) {
        if (root->type == YAML_NODE_SEQUENCE) {
            size_t count = yaml_size(root);
            for (size_t i = 0; i < count; i++) {
                struct yaml_node *entry = yaml_get_index(root, i);
                if (!entry || entry->type != YAML_NODE_MAPPING)
                    continue;

                const char *agent_id = yaml_as_string(yaml_get(entry, "agent"), "*");
                const char *action = yaml_as_string(yaml_get(entry, "action"), "*");
                const char *resource = cupolas_permission_rule_resource(entry);
                int allow = cupolas_permission_rule_allow(entry, 1);
                int priority = (int)yaml_as_int64(yaml_get(entry, "priority"), DEFAULT_PRIORITY);

                permission_rule_t *rule =
                    cupolas_permission_create_rule(agent_id, action, resource, allow, priority);
                if (!rule) {
                    yaml_destroy(doc);
                    cupolas_permission_free_rules(new_rules);
                    return cupolas_ERROR_NO_MEMORY;
                }
                *tail = rule;
                tail = &rule->next;
            }
        } else if (root->type == YAML_NODE_MAPPING) {
            struct yaml_node *rules_node = yaml_get(root, "rules");
            if (rules_node && rules_node->type == YAML_NODE_SEQUENCE) {
                size_t count = yaml_size(rules_node);
                for (size_t i = 0; i < count; i++) {
                    struct yaml_node *entry = yaml_get_index(rules_node, i);
                    if (!entry || entry->type != YAML_NODE_MAPPING)
                        continue;

                    const char *agent_id = yaml_as_string(yaml_get(entry, "agent"), "*");
                    const char *action = yaml_as_string(yaml_get(entry, "action"), "*");
                    const char *resource = cupolas_permission_rule_resource(entry);

                    int allow = cupolas_permission_rule_allow(entry, 0);
                    int priority =
                        (int)yaml_as_int64(yaml_get(entry, "priority"), DEFAULT_PRIORITY);

                    permission_rule_t *rule =
                        cupolas_permission_create_rule(agent_id, action, resource, allow, priority);
                    if (!rule) {
                        yaml_destroy(doc);
                        cupolas_permission_free_rules(new_rules);
                        return cupolas_ERROR_NO_MEMORY;
                    }
                    *tail = rule;
                    tail = &rule->next;
                }
            }
        }
    }

    yaml_destroy(doc);

    airy_rwlock_wrlock(&mgr->rwlock);
    permission_rule_t *old_rules = mgr->rules;
    mgr->rules = new_rules;
    mgr->last_mtime = mtime;
    atomic_fetch_add_32(&mgr->version, 1, memory_order_seq_cst);
    airy_rwlock_unlock(&mgr->rwlock);

    cupolas_permission_free_rules(old_rules);

    return cupolas_OK;
}

int rule_manager_match(rule_manager_t *mgr, const char *agent_id, const char *action,
                       const char *resource, const char *context)
{
    (void)context;

    if (!mgr)
        return 0;

    int best_priority = -1;
    int result = 0;

    airy_rwlock_rdlock(&mgr->rwlock);

    permission_rule_t *rule = mgr->rules;
    while (rule) {
        if (rule->priority <= best_priority) {
            rule = rule->next;
            continue;
        }

        int match = 1;

        if (rule->agent_id && agent_id) {
            if (strcmp(rule->agent_id, "*") != 0 && strcmp(rule->agent_id, agent_id) != 0) {
                match = 0;
            }
        }

        if (match && rule->action && action) {
            if (strcmp(rule->action, "*") != 0 && strcmp(rule->action, action) != 0) {
                match = 0;
            }
        }

        if (match && rule->resource && resource) {
            if (!cupolas_permission_match_pattern(rule->resource, resource)) {
                match = 0;
            }
        }

        if (match) {
            best_priority = rule->priority;
            result = rule->allow;
        }

        rule = rule->next;
    }

    airy_rwlock_unlock(&mgr->rwlock);

    return result;
}

int rule_manager_add(rule_manager_t *mgr, const char *agent_id, const char *action,
                     const char *resource, int allow, int priority)
{
    if (!mgr)
        return cupolas_ERROR_INVALID_ARG;

    permission_rule_t *rule =
        cupolas_permission_create_rule(agent_id, action, resource, allow, priority);
    if (!rule)
        return cupolas_ERROR_NO_MEMORY;

    airy_rwlock_wrlock(&mgr->rwlock);

    permission_rule_t **pp = &mgr->rules;
    while (*pp && (*pp)->priority >= priority) {
        pp = &(*pp)->next;
    }

    rule->next = *pp;
    *pp = rule;

    atomic_fetch_add_32(&mgr->version, 1, memory_order_seq_cst);

    airy_rwlock_unlock(&mgr->rwlock);

    return cupolas_OK;
}

void rule_manager_clear(rule_manager_t *mgr)
{
    if (!mgr)
        return;

    airy_rwlock_wrlock(&mgr->rwlock);
    cupolas_permission_free_rules(mgr->rules);
    mgr->rules = NULL;
    atomic_fetch_add_32(&mgr->version, 1, memory_order_seq_cst);
    airy_rwlock_unlock(&mgr->rwlock);
}

size_t rule_manager_count(rule_manager_t *mgr)
{
    if (!mgr)
        return 0;

    airy_rwlock_rdlock(&mgr->rwlock);

    size_t count = 0;
    permission_rule_t *rule = mgr->rules;
    while (rule) {
        count++;
        rule = rule->next;
    }

    airy_rwlock_unlock(&mgr->rwlock);

    return count;
}
