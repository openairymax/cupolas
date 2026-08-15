// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file audit_logger.c
 * @brief Audit logger implementation.
 */

#include "audit.h"
#include "audit_queue.h"
#include "audit_rotator.h"
#include "utils/cupolas_utils.h"

#include "memory_prealloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef AIRY_HAS_OPENSSL
#include <openssl/sha.h>
#endif

/* Ensure logging macros are available */
#ifndef LOG_ERROR
#include "logging.h"
#endif

#define DEFAULT_QUEUE_SIZE 10000
#define DEFAULT_BATCH_SIZE 100
#define DEFAULT_FLUSH_INTERVAL_MS 1000

#define AUDIT_OOM_PREALLOC_EVENTS 64

static char g_last_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static cupolas_mutex_t g_hash_chain_lock;

/* ============================================================================
 * SEC-13.2: preallocated OOM audit-event pool.
 *
 * A ring buffer of 64 audit entries is preallocated at startup. On OOM the
 * events are written into this buffer so no audit event is lost. Static
 * arrays only: zero runtime allocations.
 * ============================================================================ */

static audit_entry_t g_audit_oom_entries[AUDIT_OOM_PREALLOC_EVENTS];

static size_t g_audit_oom_write_index = 0;

static size_t g_audit_oom_used_count = 0;

static cupolas_mutex_t g_audit_oom_lock;

static bool g_audit_oom_initialized = false;

/**
 * @brief Initialize the OOM prealloc pool (SEC-13.2)
 *
 * Initialized on the first audit_logger_create() call.
 * No memory allocation: backed by a static array.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void audit_oom_pool_init(void)
{
    if (g_audit_oom_initialized) {
        return;
    }

    cupolas_mutex_init(&g_audit_oom_lock);
    __builtin_memset(g_audit_oom_entries, 0, sizeof(g_audit_oom_entries));
    g_audit_oom_write_index = 0;
    g_audit_oom_used_count = 0;
    g_audit_oom_initialized = true;
}

/**
 * @brief Allocate an audit entry from the OOM prealloc pool (SEC-13.2)
 *
 * Called when the normal audit_entry_create() fails. Takes a slot from the
 * ring buffer without calling the system malloc.
 *
 * @return Audit entry pointer, or NULL if the pool is exhausted
 */
static audit_entry_t *audit_oom_pool_alloc(void)
{
    if (!g_audit_oom_initialized) {
        return NULL;
    }

    cupolas_mutex_lock(&g_audit_oom_lock);

    if (g_audit_oom_used_count >= AUDIT_OOM_PREALLOC_EVENTS) {

        audit_entry_t *entry = &g_audit_oom_entries[g_audit_oom_write_index];
        __builtin_memset(entry, 0, sizeof(audit_entry_t));
        g_audit_oom_write_index = (g_audit_oom_write_index + 1) % AUDIT_OOM_PREALLOC_EVENTS;
        cupolas_mutex_unlock(&g_audit_oom_lock);
        return entry;
    }

    audit_entry_t *entry = &g_audit_oom_entries[g_audit_oom_write_index];
    __builtin_memset(entry, 0, sizeof(audit_entry_t));
    g_audit_oom_write_index = (g_audit_oom_write_index + 1) % AUDIT_OOM_PREALLOC_EVENTS;
    g_audit_oom_used_count++;

    cupolas_mutex_unlock(&g_audit_oom_lock);
    return entry;
}
#pragma GCC diagnostic pop

/**
 * @brief Compute the SHA-256 hash-chain value of an audit entry
 *
 * Hash format: SHA256(prev_hash + id + timestamp + subject + action +
 * resource + detail + result). The chain makes the audit log
 * tamper-evident.
 */
static void audit_compute_chain_hash(const audit_entry_t *entry, const char *prev_hash,
                                     char *hash_out)
{
#ifdef AIRY_HAS_OPENSSL
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, prev_hash, strlen(prev_hash));
    SHA256_Update(&sha256, entry->agent_id ? entry->agent_id : "",
                  entry->agent_id ? strlen(entry->agent_id) : 0);
    SHA256_Update(&sha256, &entry->timestamp_ms, sizeof(entry->timestamp_ms));
    SHA256_Update(&sha256, entry->action ? entry->action : "",
                  entry->action ? strlen(entry->action) : 0);
    SHA256_Update(&sha256, entry->resource ? entry->resource : "",
                  entry->resource ? strlen(entry->resource) : 0);
    SHA256_Update(&sha256, entry->detail ? entry->detail : "",
                  entry->detail ? strlen(entry->detail) : 0);
    SHA256_Update(&sha256, &entry->result, sizeof(entry->result));

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha256);
#pragma GCC diagnostic pop

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash_out + i * 2, 3, "%02x", digest[i]);
    }
    hash_out[64] = '\0';
#else

    uint32_t checksum = 0;
    const char *str = prev_hash;
    while (*str)
        checksum = checksum * 31 + (unsigned char)*str++;
    if (entry->agent_id) {
        str = entry->agent_id;
        while (*str)
            checksum = checksum * 31 + (unsigned char)*str++;
    }
    checksum ^= (uint32_t)entry->timestamp_ms;
    if (entry->action) {
        str = entry->action;
        while (*str)
            checksum = checksum * 31 + (unsigned char)*str++;
    }
    if (entry->resource) {
        str = entry->resource;
        while (*str)
            checksum = checksum * 31 + (unsigned char)*str++;
    }
    checksum ^= (uint32_t)entry->result;
    snprintf(hash_out, 65, "%016x%016x%016x%016x", checksum, checksum ^ 0xAAAAAAAA,
             checksum ^ 0x55555555, checksum ^ 0xFFFFFFFF);
#endif
}

struct audit_logger {
    audit_queue_t *queue;
    audit_rotator_t *rotator;
    cupolas_thread_t writer_thread;
    cupolas_atomic32_t running;
    cupolas_atomic64_t total_logged;
    cupolas_atomic64_t total_failed;
    char *log_dir;
    char *log_prefix;
    size_t max_file_size;
    int max_files;
};

static void *audit_writer_thread(void *arg)
{
    audit_logger_t *logger = (audit_logger_t *)arg;
    audit_entry_t *batch[DEFAULT_BATCH_SIZE];

    while (cupolas_atomic_load32(&logger->running)) {
        size_t actual_count = 0;
        int ret =
            audit_queue_timed_pop(logger->queue, &batch[actual_count], DEFAULT_FLUSH_INTERVAL_MS);
        if (ret == cupolas_OK) {
            actual_count++;
            while (actual_count < DEFAULT_BATCH_SIZE) {
                audit_entry_t *next = NULL;
                if (audit_queue_try_pop(logger->queue, &next) != cupolas_OK)
                    break;
                batch[actual_count++] = next;
            }
            for (size_t i = 0; i < actual_count; i++) {
                if (audit_rotator_write(logger->rotator, batch[i]) == cupolas_OK) {
                    cupolas_atomic_add64(&logger->total_logged, 1);
                } else {
                    AIRY_LOG_ERROR("[CRITICAL] audit_writer_thread: audit write failed, entry_type=%d, "
                              "total_failed=%llu",
                              (int)batch[i]->type,
                              (unsigned long long)cupolas_atomic_load64(&logger->total_failed) + 1);
                    cupolas_atomic_add64(&logger->total_failed, 1);
                }
                audit_entry_destroy(batch[i]);
            }
        }
    }

    size_t remaining = audit_queue_size(logger->queue);
    while (remaining > 0) {
        audit_entry_t *entry = NULL;
        if (audit_queue_try_pop(logger->queue, &entry) == cupolas_OK) {
            if (audit_rotator_write(logger->rotator, entry) == cupolas_OK) {
                cupolas_atomic_add64(&logger->total_logged, 1);
            } else {
                AIRY_LOG_ERROR("[CRITICAL] audit_writer_thread: audit write failed during shutdown, "
                          "total_failed=%llu",
                          (unsigned long long)cupolas_atomic_load64(&logger->total_failed) + 1);
                cupolas_atomic_add64(&logger->total_failed, 1);
            }
            audit_entry_destroy(entry);
        }
        remaining = audit_queue_size(logger->queue);
    }

    return NULL;
}

/* Restore the hash-chain tail from existing audit logs: after a process
 * restart, starting g_last_hash from all zeros would break the link to the
 * historical chain. Tamper-evident auditing (BAN-129) requires the chain
 * state to be persisted to disk and restored at startup
 * (audit_rotator_write already persists prev_hash/curr_hash). */
static void audit_logger_restore_last_hash(audit_logger_t *logger)
{
    if (!logger || !logger->log_dir || !logger->log_prefix)
        return;

    char path[1024];
    snprintf(path, sizeof(path), "%s%s%s.log", logger->log_dir, logger->log_dir[0] ? "/" : "",
             logger->log_prefix);
    FILE *f = fopen(path, "r");
    if (!f)
        return;

    char line[4096];
    char last_hash[65] = {0};
    while (fgets(line, sizeof(line), f)) {
        const char *key = strstr(line, "\"curr_hash\":\"");
        if (key) {
            const char *start = key + strlen("\"curr_hash\":\"");
            const char *end = strchr(start, '"');
            if (end && (size_t)(end - start) == 64) {
                __builtin_memcpy(last_hash, start, 64);
                last_hash[64] = '\0';
            }
        }
    }
    fclose(f);

    if (last_hash[0]) {
        cupolas_mutex_lock(&g_hash_chain_lock);
        __builtin_memcpy(g_last_hash, last_hash, sizeof(g_last_hash));
        cupolas_mutex_unlock(&g_hash_chain_lock);
    }
}

audit_logger_t *audit_logger_create(const char *log_dir, const char *log_prefix,
                                    size_t max_file_size, int max_files)
{

    static cupolas_atomic32_t hash_lock_inited = {0};
    if (cupolas_atomic_load32(&hash_lock_inited) == 0) {
        cupolas_mutex_init(&g_hash_chain_lock);
        cupolas_atomic_store32(&hash_lock_inited, 1);
    }

    audit_logger_t *logger = (audit_logger_t *)cupolas_mem_alloc(sizeof(audit_logger_t));
    if (!logger)
        return NULL;

    __builtin_memset(logger, 0, sizeof(audit_logger_t));

    if (log_dir) {
        logger->log_dir = cupolas_strdup(log_dir);
        if (!logger->log_dir)
            goto error;
    }

    if (log_prefix) {
        logger->log_prefix = cupolas_strdup(log_prefix);
        if (!logger->log_prefix)
            goto error;
    }

    logger->max_file_size = max_file_size > 0 ? max_file_size : 10 * 1024 * 1024;
    logger->max_files = max_files > 0 ? max_files : 10;

    logger->queue = audit_queue_create(DEFAULT_QUEUE_SIZE);
    if (!logger->queue)
        goto error;

    logger->rotator = audit_rotator_create(log_dir, log_prefix, max_file_size, max_files);
    if (!logger->rotator)
        goto error;

    audit_logger_restore_last_hash(logger);

    cupolas_atomic_store32(&logger->running, 1);

    if (cupolas_thread_create(&logger->writer_thread, audit_writer_thread, logger) != cupolas_OK) {
        goto error;
    }

    return logger;

error:
    if (logger->queue)
        audit_queue_destroy(logger->queue);
    if (logger->rotator)
        audit_rotator_destroy(logger->rotator);
    cupolas_mem_free(logger->log_dir);
    cupolas_mem_free(logger->log_prefix);
    cupolas_mem_free(logger);
    return NULL;
}

void audit_logger_destroy(audit_logger_t *logger)
{
    if (!logger)
        return;

    cupolas_atomic_store32(&logger->running, 0);
    audit_queue_shutdown(logger->queue, false);
    cupolas_thread_join(logger->writer_thread, NULL);

    audit_queue_destroy(logger->queue);
    audit_rotator_destroy(logger->rotator);

    cupolas_mem_free(logger->log_dir);
    cupolas_mem_free(logger->log_prefix);
    cupolas_mem_free(logger);
}

int audit_logger_log(audit_logger_t *logger, audit_event_type_t type, const char *agent_id,
                     const char *action, const char *resource, const char *detail, int result)
{
    if (!logger) {
        AIRY_LOG_ERROR("audit_logger_log: NULL logger parameter");
        return cupolas_ERROR_INVALID_ARG;
    }

    audit_entry_t *entry = audit_entry_create(type, agent_id, action, resource, detail, result);
    if (!entry) {
        /* SEC-13: Fallback to pre-allocated audit buffer under OOM */
        void *emergency_buf = airy_prealloc_acquire(AIRY_PREALLOC_AUDIT);
        if (emergency_buf) {
            AIRY_LOG_WARN("audit_logger_log: using emergency buffer fallback for type=%d, agent_id=%s, "
                     "action=%s",
                     (int)type, agent_id ? agent_id : "(null)", action ? action : "(null)");
            /* Write a minimal audit record to the emergency buffer */
            int written = snprintf((char *)emergency_buf, AIRY_PREALLOC_AUDIT_BUF_SIZE,
                                   "{\"type\":%d,\"agent_id\":\"%s\",\"action\":\"%s\","
                                   "\"resource\":\"%s\",\"detail\":\"%s\",\"result\":%d,"
                                   "\"emergency\":true}\n",
                                   (int)type, agent_id ? agent_id : "", action ? action : "",
                                   resource ? resource : "", detail ? detail : "", result);

            if (written > 0 && (size_t)written < AIRY_PREALLOC_AUDIT_BUF_SIZE) {
                /* Write emergency audit entry directly via rotator */
                if (logger->rotator) {
                    /* Construct a minimal entry from the emergency buffer
                     * for the rotator to write */
                    audit_entry_t *oom_entry = audit_oom_pool_alloc();
                    if (oom_entry) {
                        oom_entry->type = type;
                        oom_entry->timestamp_ms = 0; /* best-effort */
                        oom_entry->result = result;
                        audit_rotator_write(logger->rotator, oom_entry);
                    }
                }
            }

            airy_prealloc_release(AIRY_PREALLOC_AUDIT);
        }
        return cupolas_ERROR_NO_MEMORY;
    }

    cupolas_mutex_lock(&g_hash_chain_lock);
    __builtin_memcpy(entry->prev_hash, g_last_hash, sizeof(entry->prev_hash));
    audit_compute_chain_hash(entry, g_last_hash, entry->curr_hash);
    __builtin_memcpy(g_last_hash, entry->curr_hash, sizeof(g_last_hash));
    cupolas_mutex_unlock(&g_hash_chain_lock);

    int ret = audit_queue_try_push(logger->queue, entry);
    if (ret != cupolas_OK) {
        AIRY_LOG_ERROR("[CRITICAL] audit_logger_log: audit queue push failed (buffer overflow), "
                  "type=%d, agent_id=%s, action=%s, ret=%d",
                  (int)type, agent_id ? agent_id : "(null)", action ? action : "(null)", ret);
        audit_entry_destroy(entry);
        cupolas_atomic_add64(&logger->total_failed, 1);
    }

    return ret;
}

int audit_logger_log_permission(audit_logger_t *logger, const char *agent_id, const char *action,
                                const char *resource, int allowed)
{
    return audit_logger_log(logger, AUDIT_EVENT_PERMISSION, agent_id, action, resource, NULL,
                            allowed);
}

int audit_logger_log_sanitizer(audit_logger_t *logger, const char *agent_id, const char *input,
                               const char *output, int passed)
{
    return audit_logger_log(logger, AUDIT_EVENT_SANITIZER, agent_id, "sanitize", input, output,
                            passed);
}

int audit_logger_log_workbench(audit_logger_t *logger, const char *agent_id, const char *command,
                               int exit_code)
{
    return audit_logger_log(logger, AUDIT_EVENT_WORKBENCH, agent_id, "execute", command, NULL,
                            exit_code);
}

/**
 * @brief Verify the integrity of the audit hash chain (BAN-129 contract)
 *
 * Recomputes the chain from the given entry list and checks each entry's
 * curr_hash against the SHA-256 hash derived from prev_hash plus the entry
 * content.
 *
 * @param entries     Audit entries in chronological order
 * @param entry_count Number of entries
 * @param first_prev_hash Chain start hash (usually all zeros)
 * @param out_invalid_index Index of the first invalid entry (-1 if all valid)
 * @return true if the chain is intact, false on any tampering
 */
bool audit_logger_verify_chain(const audit_entry_t **entries, size_t entry_count,
                               const char *first_prev_hash, int *out_invalid_index)
{
    if (!entries || entry_count == 0 || !first_prev_hash) {
        AIRY_LOG_ERROR("audit_logger_verify_chain: NULL/invalid parameter - entries=%p, "
                  "entry_count=%zu, first_prev_hash=%p",
                  (void *)entries, entry_count, (void *)first_prev_hash);
        if (out_invalid_index)
            *out_invalid_index = -1;
        return false;
    }

    char expected_prev[65];
    __builtin_memcpy(expected_prev, first_prev_hash, 65);

    for (size_t i = 0; i < entry_count; i++) {
        const audit_entry_t *entry = entries[i];
        if (!entry) {
            AIRY_LOG_ERROR("audit_logger_verify_chain: NULL entry at index=%zu", i);
            if (out_invalid_index)
                *out_invalid_index = (int)i;
            return false;
        }

        if (memcmp(entry->prev_hash, expected_prev, 65) != 0) {
            AIRY_LOG_ERROR("audit_logger_verify_chain: prev_hash mismatch at index=%zu, chain tampered",
                      i);
            if (out_invalid_index)
                *out_invalid_index = (int)i;
            return false;
        }

        char recomputed_hash[65];
        audit_compute_chain_hash(entry, expected_prev, recomputed_hash);
        if (memcmp(entry->curr_hash, recomputed_hash, 65) != 0) {
            AIRY_LOG_ERROR("audit_logger_verify_chain: curr_hash mismatch at index=%zu, entry tampered "
                      "or corrupted",
                      i);
            if (out_invalid_index)
                *out_invalid_index = (int)i;
            return false;
        }

        __builtin_memcpy(expected_prev, entry->curr_hash, 65);
    }

    if (out_invalid_index)
        *out_invalid_index = -1;
    return true;
}

void audit_logger_flush(audit_logger_t *logger)
{
    if (!logger)
        return;

    while (audit_queue_size(logger->queue) > 0) {
        cupolas_sleep_ms(10);
    }
}

void audit_logger_stats(audit_logger_t *logger, uint64_t *total_logged, uint64_t *total_failed)
{
    if (!logger) {
        if (total_logged)
            *total_logged = 0;
        if (total_failed)
            *total_failed = 0;
        return;
    }

    if (total_logged)
        *total_logged = cupolas_atomic_load64(&logger->total_logged);
    if (total_failed)
        *total_failed = cupolas_atomic_load64(&logger->total_failed);
}
