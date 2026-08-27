// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_entitlements_crypto.c
 * @brief Entitlements signature verify/sign domain (OpenSSL).
 * @details 从 cupolas_entitlements.c 拆出的密码学职责域：模块生命周期
 *          （OpenSSL 全局初始化）、SHA-256 签名验证/生成与 fail-closed
 *          预仲裁检查。不接触解析/权限仲裁逻辑。
 */

#include "cupolas_entitlements_internal.h"

#include "cupolas_error.h"
#include "airy_memory.h"
#include "atomic_compat.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static atomic_int g_initialized = 0;

int cupolas_entitlements_init(void)
{
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(&g_initialized, &expected, 1, memory_order_seq_cst,
                                                memory_order_seq_cst)) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    return 0;
}

void cupolas_entitlements_cleanup(void)
{
    if (!atomic_load_explicit(&g_initialized, memory_order_acquire))
        return;

    EVP_cleanup();
    ERR_free_strings();

    atomic_store_explicit(&g_initialized, 0, memory_order_seq_cst);
}

int cupolas_entitlements_verify(cupolas_entitlements_t *entitlements, const char *public_key)
{
    if (!entitlements || !public_key)
        return CUPOLAS_ENT_INVALID;
    if (!entitlements->signature || entitlements->sig_len == 0)
        return CUPOLAS_ENT_SIGNATURE_INVALID;

    BIO *bio = BIO_new_mem_buf(public_key, -1);
    if (!bio)
        return CUPOLAS_ENT_SIGNATURE_INVALID;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey)
        return CUPOLAS_ENT_SIGNATURE_INVALID;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return CUPOLAS_ENT_SIGNATURE_INVALID;
    }

    int result = CUPOLAS_ENT_SIGNATURE_INVALID;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        size_t content_len = strlen(entitlements->raw_content);
        if (EVP_DigestVerify(md_ctx, (unsigned char *)entitlements->signature,
                             entitlements->sig_len, (unsigned char *)entitlements->raw_content,
                             content_len) == 1) {
            result = CUPOLAS_ENT_OK;
            entitlements->is_verified = 1;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return result;
}

int cupolas_entitlements_sign(cupolas_entitlements_t *entitlements, const char *private_key,
                              char *signature_out, size_t *sig_len)
{
    if (!entitlements || !private_key || !signature_out || !sig_len)
        return CUPOLAS_ENT_INVALID;

    BIO *bio = BIO_new_mem_buf(private_key, -1);
    if (!bio)
        return CUPOLAS_ENT_PARSE_ERROR;

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey)
        return CUPOLAS_ENT_PARSE_ERROR;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return CUPOLAS_ENT_PARSE_ERROR;
    }

    int result = CUPOLAS_ENT_PARSE_ERROR;

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        size_t content_len = strlen(entitlements->raw_content);
        size_t req_len = 0;

        if (EVP_DigestSign(md_ctx, NULL, &req_len, (unsigned char *)entitlements->raw_content,
                           content_len) == 1) {
            if (*sig_len >= req_len) {
                if (EVP_DigestSign(md_ctx, (unsigned char *)signature_out, sig_len,
                                   (unsigned char *)entitlements->raw_content, content_len) == 1) {
                    result = CUPOLAS_ENT_OK;

                    AIRY_FREE(entitlements->signature);
                    entitlements->signature = (char *)AIRY_MALLOC(*sig_len);
                    if (entitlements->signature) {
                        __builtin_memcpy(entitlements->signature, signature_out, *sig_len);
                        entitlements->sig_len = *sig_len;
                    }
                }
            }
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return result;
}

bool cupolas_entitlements_is_signed(cupolas_entitlements_t *entitlements)
{
    if (!entitlements)
        return false;
    return entitlements->signature != NULL && entitlements->sig_len > 0;
}

/* Unified pre-arbitration check (fail-closed): entitlements must have
 * passed signature verification (is_verified==1) and still be within their
 * validity period. Unverified/tampered/expired entitlements are always
 * rejected -- signature validation and permission arbitration must not be
 * decoupled, otherwise arbitration would proceed on tampered entitlements
 * (a security flaw). */
int entitlements_verified_valid(cupolas_entitlements_t *entitlements)
{
    if (!entitlements)
        return 0;
    if (!entitlements->is_verified)
        return 0;
    return cupolas_entitlements_check_validity(entitlements) == CUPOLAS_ENT_OK;
}
