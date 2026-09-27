// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_runtime_protection_integrity.c - Runtime Protection integrity domain
 */

/**
 * @file cupolas_runtime_protection_integrity.c
 * @brief Enhanced Runtime Protection - integrity domain (functional domain
 *        after cupolas_runtime_protection.c split).
 *
 * 语义定稿（与公开头契约逐条对齐）：
 *  - code 完整性：运行镜像文件整体 SHA-256 基线认证（ELF/PE/Mach-O 三端
 *    可移植，检测落盘篡改与替换；内存态代码改写由 CFI 与 W^X 分层覆盖）；
 *  - data 完整性：防护模块自身关键状态（配置快照 + 基线标志）SHA-256 自证，
 *    检测运行期对防护配置与回调的内存篡改；
 *  - ro_sections：Linux /proc/self/maps 的 W^X 审计，RWX 私有映射即违例，
 *    非 Linux 端该能力缺位（与 memory 域同款按平台分级模式）；
 *  - self_check：check_interval_ms 周期自检线程，统一由
 *    cupolas_rtp_integrity_shutdown() 在模块 cleanup 时 join。
 * @author SPHARX Ltd. - Airymax Team
 */

#include "cupolas_runtime_protection.h"
#include "cupolas_runtime_protection_internal.h"

#include "airy_memory.h"
#include "string_compat.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "error.h"

#define RTP_HASH_LEN 32
#define RTP_TICK_MS 50
#define RTP_SNAPSHOT_CAP 256

static int rtp_self_path(char *buf, size_t cap)
{
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
    return (n > 0 && n < cap) ? 0 : AIRY_EIO;
#elif defined(__linux__)
    ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n <= 0)
        return AIRY_EIO;
    buf[n] = '\0';
    return 0;
#elif defined(__APPLE__)
    uint32_t size = (uint32_t)cap;
    return (_NSGetExecutablePath(buf, &size) == 0) ? 0 : AIRY_EIO;
#else
    (void)buf;
    (void)cap;
    return AIRY_ENOTSUP;
#endif
}

static int rtp_sha256_file(const char *path, uint8_t out[RTP_HASH_LEN])
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return AIRY_EIO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buf[65536];
    unsigned int md_len = 0;
    size_t n = 1;
    int rc = AIRY_EIO;

    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
            if (EVP_DigestUpdate(ctx, buf, n) != 1)
                break;
        }
        if (n == 0 && !ferror(fp) && EVP_DigestFinal_ex(ctx, out, &md_len) == 1 &&
            md_len == RTP_HASH_LEN)
            rc = 0;
    }

    if (ctx)
        EVP_MD_CTX_free(ctx);
    fclose(fp);
    return rc;
}

static void rtp_state_snapshot(uint8_t *buf, size_t *len)
{
    const cupolas_runtime_protect_config_t *m = &g_runtime_prot.manager;
    size_t o = 0;

#define RTP_PUSH8(v) (buf[o++] = (uint8_t)(v))
#define RTP_PUSH32(v)                       \
    do {                                    \
        uint32_t _v = (uint32_t)(v);        \
        buf[o] = (uint8_t)_v;               \
        buf[o + 1] = (uint8_t)(_v >> 8);    \
        buf[o + 2] = (uint8_t)(_v >> 16);   \
        buf[o + 3] = (uint8_t)(_v >> 24);   \
        o += 4;                             \
    } while (0)
#define RTP_PUSH_PTR(v)                                     \
    do {                                                    \
        uintptr_t _p = (uintptr_t)(v);                      \
        for (unsigned _i = 0; _i < sizeof(uintptr_t); _i++) \
            buf[o++] = (uint8_t)(_p >> (8 * _i));           \
    } while (0)

    RTP_PUSH32(m->level);
    RTP_PUSH32(g_runtime_prot.status);

    RTP_PUSH8(m->memory.enable_aslr);
    RTP_PUSH8(m->memory.enable_dep);
    RTP_PUSH8(m->memory.enable_stack_protector);
    RTP_PUSH8(m->memory.enable_heap_guard);
    RTP_PUSH8(m->memory.enable_mprotect);
    RTP_PUSH8(m->memory.enable_guard_pages);
    RTP_PUSH32(m->memory.stack_canary_type);

    RTP_PUSH8(m->cfi.enable_cfi);
    RTP_PUSH8(m->cfi.enable_safestack);
    RTP_PUSH8(m->cfi.enable_shadow_stack);
    RTP_PUSH8(m->cfi.enable_ibt);
    RTP_PUSH8(m->cfi.enable_cet);
    RTP_PUSH32(m->cfi.cfi_level);

    RTP_PUSH8(m->seccomp.enable_seccomp);
    RTP_PUSH8(m->seccomp.enable_seccomp_bpf);
    RTP_PUSH32(m->seccomp.default_action);

    RTP_PUSH8(m->integrity.enable_code_integrity);
    RTP_PUSH8(m->integrity.enable_data_integrity);
    RTP_PUSH8(m->integrity.enable_ro_sections);
    RTP_PUSH8(m->integrity.enable_self_check);
    RTP_PUSH32(m->integrity.check_interval_ms);
    RTP_PUSH32(m->integrity.hash_algorithm);

    RTP_PUSH8(m->enable_audit);
    RTP_PUSH8(m->enable_violation_handler);
    RTP_PUSH_PTR(m->violation_callback);
    RTP_PUSH_PTR(g_runtime_prot.violation_callback);
    RTP_PUSH_PTR(g_runtime_prot.integrity_callback);
    RTP_PUSH8(g_runtime_prot.hashes_computed);

#undef RTP_PUSH8
#undef RTP_PUSH32
#undef RTP_PUSH_PTR
    *len = o;
}

static int rtp_state_hash(uint8_t out[RTP_HASH_LEN])
{
    uint8_t buf[RTP_SNAPSHOT_CAP];
    size_t len = 0;
    unsigned int md_len = 0;

    AIRY_MEMSET(buf, 0, sizeof(buf));
    cupolas_mutex_lock(&g_runtime_prot.lock);
    rtp_state_snapshot(buf, &len);
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    if (EVP_Digest(buf, len, out, &md_len, EVP_sha256(), NULL) != 1 || md_len != RTP_HASH_LEN)
        return AIRY_EIO;
    return 0;
}

static int rtp_wx_scan(void)
{
#if defined(__linux__)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return AIRY_EIO;

    char line[512];
    int rc = 0;

    while (fgets(line, sizeof(line), fp)) {
        const char *perms = strchr(line, ' ');
        if (!perms)
            continue;
        while (*perms == ' ')
            perms++;
        if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            rc = AIRY_EACCES;
            break;
        }
    }

    fclose(fp);
    return rc;
#else
    return 0;
#endif
}

static int rtp_fail(int rc, const char *detail)
{
    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.stats.integrity_failures++;
    g_runtime_prot.status = CUPOLAS_PROTECT_STATUS_COMPROMISED;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    cupolas_record_violation(CUPOLAS_VIOLATION_INTEGRITY, detail, NULL);

    void (*cb)(int) = g_runtime_prot.integrity_callback;
    if (cb)
        cb(rc);
    return rc;
}

static void *rtp_integrity_thread(void *arg)
{
    (void)arg;

    uint32_t interval = g_runtime_prot.manager.integrity.check_interval_ms;
    uint32_t elapsed = 0;

    while (!atomic_load(&g_runtime_prot.integrity_stop)) {
        cupolas_sleep_ms(RTP_TICK_MS);
        elapsed += RTP_TICK_MS;
        if (elapsed >= interval) {
            elapsed = 0;
            (void)cupolas_integrity_check();
        }
    }
    return NULL;
}

int cupolas_integrity_compute_code_hash(uint8_t *hash_out)
{
    if (!hash_out)
        return AIRY_EINVAL;

    char path[4096];
    int rc = rtp_self_path(path, sizeof(path));
    if (rc != 0)
        return rc;
    return rtp_sha256_file(path, hash_out);
}

int cupolas_integrity_verify_code(const uint8_t *expected_hash)
{
    if (!expected_hash)
        return AIRY_EINVAL;

    uint8_t cur[RTP_HASH_LEN];
    int rc = cupolas_integrity_compute_code_hash(cur);
    if (rc != 0)
        return rc;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.stats.integrity_checks++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return (CRYPTO_memcmp(cur, expected_hash, RTP_HASH_LEN) == 0) ? 0 : AIRY_EACCES;
}

int cupolas_integrity_verify_data(const uint8_t *expected_hash)
{
    if (!expected_hash)
        return AIRY_EINVAL;

    uint8_t cur[RTP_HASH_LEN];
    int rc = rtp_state_hash(cur);
    if (rc != 0)
        return rc;

    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.stats.integrity_checks++;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    return (CRYPTO_memcmp(cur, expected_hash, RTP_HASH_LEN) == 0) ? 0 : AIRY_EACCES;
}

int cupolas_integrity_check(void)
{
    cupolas_mutex_lock(&g_runtime_prot.lock);
    if (!g_runtime_prot.hashes_computed) {
        cupolas_mutex_unlock(&g_runtime_prot.lock);
        return AIRY_EINVAL;
    }
    uint8_t base[RTP_HASH_LEN];
    uint8_t base_data[RTP_HASH_LEN];
    bool code_on = g_runtime_prot.manager.integrity.enable_code_integrity;
    bool data_on = g_runtime_prot.manager.integrity.enable_data_integrity;
    bool wx_on = g_runtime_prot.manager.integrity.enable_ro_sections;
    AIRY_MEMCPY(base, g_runtime_prot.code_hash, RTP_HASH_LEN);
    AIRY_MEMCPY(base_data, g_runtime_prot.data_hash, RTP_HASH_LEN);
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    int rc = 0;
    if (code_on)
        rc = cupolas_integrity_verify_code(base);
    if (rc == 0 && data_on)
        rc = cupolas_integrity_verify_data(base_data);
    if (rc == 0 && wx_on) {
        rc = rtp_wx_scan();
        if (rc != 0)
            return rtp_fail(rc, "RWX mapping detected");
    }
    if (rc == 0)
        return 0;
    return rtp_fail(rc, "Integrity baseline mismatch");
}

int cupolas_integrity_enable(const cupolas_integrity_config_t *config)
{
    if (!config)
        return AIRY_EINVAL;
    if (config->hash_algorithm != 0 && config->hash_algorithm != CUPOLAS_HASH_SHA256)
        return AIRY_EINVAL;
    if (config->enable_self_check && config->check_interval_ms == 0)
        return AIRY_EINVAL;

    cupolas_rtp_integrity_shutdown();

    cupolas_mutex_lock(&g_runtime_prot.lock);
    AIRY_MEMSET(g_runtime_prot.code_hash, 0, RTP_HASH_LEN);
    AIRY_MEMSET(g_runtime_prot.data_hash, 0, RTP_HASH_LEN);
    g_runtime_prot.hashes_computed = 1;
    cupolas_mutex_unlock(&g_runtime_prot.lock);

    if (config->enable_code_integrity) {
        uint8_t hash[RTP_HASH_LEN];
        int rc = cupolas_integrity_compute_code_hash(hash);
        if (rc != 0)
            return rc;
        cupolas_mutex_lock(&g_runtime_prot.lock);
        AIRY_MEMCPY(g_runtime_prot.code_hash, hash, RTP_HASH_LEN);
        cupolas_mutex_unlock(&g_runtime_prot.lock);
    }

    if (config->enable_data_integrity) {
        uint8_t hash[RTP_HASH_LEN];
        int rc = rtp_state_hash(hash);
        if (rc != 0)
            return rc;
        cupolas_mutex_lock(&g_runtime_prot.lock);
        AIRY_MEMCPY(g_runtime_prot.data_hash, hash, RTP_HASH_LEN);
        cupolas_mutex_unlock(&g_runtime_prot.lock);
    }

    if (config->enable_ro_sections) {
        int rc = rtp_wx_scan();
        if (rc != 0) {
            cupolas_record_violation(CUPOLAS_VIOLATION_RESOURCE, "RWX mapping detected", NULL);
            return rc;
        }
    }

    if (config->enable_self_check) {
        atomic_store(&g_runtime_prot.integrity_stop, 0);
        if (cupolas_thread_create(&g_runtime_prot.integrity_thread, rtp_integrity_thread, NULL) !=
            0)
            return AIRY_EIO;
        g_runtime_prot.integrity_thread_active = 1;
    }

    return 0;
}

int cupolas_integrity_set_callback(void (*callback)(int result))
{
    cupolas_mutex_lock(&g_runtime_prot.lock);
    g_runtime_prot.integrity_callback = callback;
    cupolas_mutex_unlock(&g_runtime_prot.lock);
    return 0;
}

void cupolas_rtp_integrity_shutdown(void)
{
    if (!g_runtime_prot.integrity_thread_active)
        return;

    atomic_store(&g_runtime_prot.integrity_stop, 1);
    cupolas_thread_join(g_runtime_prot.integrity_thread, NULL);
    g_runtime_prot.integrity_thread_active = 0;
}
