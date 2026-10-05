// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * audit_queue.c - Audit Log Queue Implementation: Thread-safe Producer-Consumer Queue
 */

/**
 * @file audit_queue.c
 * @brief Audit Log Queue Implementation - Thread-safe Producer-Consumer Queue
 * @author SPHARX Ltd. - Airymax Team
 */

#include "platform.h"
#include "atomic_compat.h"
#include "audit_queue.h"
#include "security/cupolas_error.h"

#include "utils/cupolas_utils.h"

#include <stdlib.h>
#include <string.h>

audit_entry_t *audit_entry_create(audit_event_type_t type, const char *agent_id, const char *action,
                                  const char *resource, const char *detail, int result)
{
    audit_entry_t *entry = (audit_entry_t *)AIRY_CALLOC(1, sizeof(audit_entry_t));
    if (!entry)
        return NULL;

    __builtin_memset(entry, 0, sizeof(audit_entry_t));

    entry->timestamp_ms = airy_time_wall_ms();
    entry->type = type;
    entry->result = result;

    if (agent_id) {
        entry->agent_id = AIRY_STRDUP(agent_id);
        if (!entry->agent_id)
            goto error;
    }
    if (action) {
        entry->action = AIRY_STRDUP(action);
        if (!entry->action)
            goto error;
    }
    if (resource) {
        entry->resource = AIRY_STRDUP(resource);
        if (!entry->resource)
            goto error;
    }
    if (detail) {
        entry->detail = AIRY_STRDUP(detail);
        if (!entry->detail)
            goto error;
    }

    return entry;

error:
    audit_entry_destroy(entry);
    return NULL;
}

void audit_entry_destroy(audit_entry_t *entry)
{
    if (!entry)
        return;

    AIRY_FREE(entry->agent_id);
    AIRY_FREE(entry->action);
    AIRY_FREE(entry->resource);
    AIRY_FREE(entry->detail);
    AIRY_FREE(entry);
}

audit_queue_t *audit_queue_create(size_t max_size)
{
    audit_queue_t *queue = (audit_queue_t *)AIRY_CALLOC(1, sizeof(audit_queue_t));
    if (!queue)
        return NULL;

    __builtin_memset(queue, 0, sizeof(audit_queue_t));
    queue->max_size = max_size;

    if (airy_mtx_init(&queue->lock) != cupolas_OK) {
        AIRY_FREE(queue);
        return NULL;
    }

    if (airy_cond_init(&queue->not_empty) != cupolas_OK) {
        airy_mtx_destroy(&queue->lock);
        AIRY_FREE(queue);
        return NULL;
    }

    if (airy_cond_init(&queue->not_full) != cupolas_OK) {
        airy_cond_destroy(&queue->not_empty);
        airy_mtx_destroy(&queue->lock);
        AIRY_FREE(queue);
        return NULL;
    }

    return queue;
}

void audit_queue_destroy(audit_queue_t *queue)
{
    if (!queue)
        return;

    airy_mtx_lock(&queue->lock);
    queue->shutdown = true;
    airy_cond_broadcast(&queue->not_empty);
    airy_cond_broadcast(&queue->not_full);

    audit_entry_t *entry = queue->head;
    while (entry) {
        audit_entry_t *next = entry->next;
        audit_entry_destroy(entry);
        entry = next;
    }

    airy_mtx_unlock(&queue->lock);

    airy_cond_destroy(&queue->not_full);
    airy_cond_destroy(&queue->not_empty);
    airy_mtx_destroy(&queue->lock);
    AIRY_FREE(queue);
}

/* Single-sourced ring mechanics: every producer/consumer mutates the
 * head/tail/size triple through these two primitives so the invariants live
 * in one place. Caller must hold queue->lock. */

static void audit_q_enqueue(audit_queue_t *queue, audit_entry_t *entry)
{
    entry->next = NULL;
    if (queue->tail)
        queue->tail->next = entry;
    else
        queue->head = entry;
    queue->tail = entry;
    queue->size++;
}

static audit_entry_t *audit_q_unlink(audit_queue_t *queue)
{
    audit_entry_t *entry = queue->head;
    queue->head = entry->next;
    if (!queue->head)
        queue->tail = NULL;
    queue->size--;
    return entry;
}

int audit_queue_push(audit_queue_t *queue, audit_entry_t *entry)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    while (queue->max_size > 0 && queue->size >= queue->max_size && !queue->shutdown) {
        airy_cond_wait(&queue->not_full, &queue->lock);
    }

    if (queue->shutdown) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_UNKNOWN;
    }

    audit_q_enqueue(queue, entry);

    atomic_fetch_add_64(&queue->total_pushed, 1, memory_order_seq_cst);

    airy_cond_signal(&queue->not_empty);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

int audit_queue_try_push(audit_queue_t *queue, audit_entry_t *entry)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    if (queue->shutdown) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_UNKNOWN;
    }

    if (queue->max_size > 0 && queue->size >= queue->max_size) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_WOULD_BLOCK;
    }

    audit_q_enqueue(queue, entry);

    atomic_fetch_add_64(&queue->total_pushed, 1, memory_order_seq_cst);

    airy_cond_signal(&queue->not_empty);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

int audit_queue_pop(audit_queue_t *queue, audit_entry_t **entry)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    while (queue->size == 0 && !queue->shutdown) {
        airy_cond_wait(&queue->not_empty, &queue->lock);
    }

    if (queue->size == 0) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_UNKNOWN;
    }

    *entry = audit_q_unlink(queue);

    atomic_fetch_add_64(&queue->total_popped, 1, memory_order_seq_cst);

    airy_cond_signal(&queue->not_full);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

int audit_queue_timed_pop(audit_queue_t *queue, audit_entry_t **entry, uint32_t timeout_ms)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    while (queue->size == 0 && !queue->shutdown) {
        int ret = airy_cond_timedwait(&queue->not_empty, &queue->lock, timeout_ms);
        if (ret == cupolas_ERROR_TIMEOUT) {
            airy_mtx_unlock(&queue->lock);
            return cupolas_ERROR_TIMEOUT;
        }
    }

    if (queue->size == 0) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_UNKNOWN;
    }

    *entry = audit_q_unlink(queue);

    atomic_fetch_add_64(&queue->total_popped, 1, memory_order_seq_cst);

    airy_cond_signal(&queue->not_full);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

int audit_queue_try_pop(audit_queue_t *queue, audit_entry_t **entry)
{
    if (!queue || !entry)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    if (queue->size == 0) {
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_WOULD_BLOCK;
    }

    *entry = audit_q_unlink(queue);

    atomic_fetch_add_64(&queue->total_popped, 1, memory_order_seq_cst);

    airy_cond_signal(&queue->not_full);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

int audit_queue_pop_batch(audit_queue_t *queue, audit_entry_t **entries, size_t max_count,
                          size_t *actual_count)
{
    if (!queue || !entries || !actual_count)
        return cupolas_ERROR_INVALID_ARG;

    airy_mtx_lock(&queue->lock);

    while (queue->size == 0 && !queue->shutdown) {
        airy_cond_wait(&queue->not_empty, &queue->lock);
    }

    if (queue->size == 0) {
        *actual_count = 0;
        airy_mtx_unlock(&queue->lock);
        return cupolas_ERROR_UNKNOWN;
    }

    size_t count = 0;
    while (count < max_count && queue->head) {
        entries[count] = audit_q_unlink(queue);
        count++;
        atomic_fetch_add_64(&queue->total_popped, 1, memory_order_seq_cst);
    }

    *actual_count = count;

    airy_cond_broadcast(&queue->not_full);
    airy_mtx_unlock(&queue->lock);

    return cupolas_OK;
}

void audit_queue_shutdown(audit_queue_t *queue, bool wait_empty)
{
    if (!queue)
        return;

    airy_mtx_lock(&queue->lock);

    if (wait_empty) {
        while (queue->size > 0) {
            airy_cond_broadcast(&queue->not_empty);
            airy_mtx_unlock(&queue->lock);
            airy_sleep_ms(10);
            airy_mtx_lock(&queue->lock);
        }
    }

    queue->shutdown = true;
    airy_cond_broadcast(&queue->not_empty);
    airy_cond_broadcast(&queue->not_full);
    airy_mtx_unlock(&queue->lock);
}

size_t audit_queue_size(audit_queue_t *queue)
{
    if (!queue)
        return 0;

    airy_mtx_lock(&queue->lock);
    size_t size = queue->size;
    airy_mtx_unlock(&queue->lock);

    return size;
}

void audit_queue_stats(audit_queue_t *queue, uint64_t *total_pushed, uint64_t *total_popped)
{
    if (!queue) {
        if (total_pushed)
            *total_pushed = 0;
        if (total_popped)
            *total_popped = 0;
        return;
    }

    if (total_pushed)
        *total_pushed = atomic_load_64(&queue->total_pushed, memory_order_seq_cst);
    if (total_popped)
        *total_popped = atomic_load_64(&queue->total_popped, memory_order_seq_cst);
}
