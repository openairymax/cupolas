// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_crypto.c
 * @brief Crypto utilities domain: type/operation string mapping and
 *        random passphrase / key-pair generation.
 */

#include "cupolas_vault_internal.h"

const char *cupolas_vault_cred_type_string(cupolas_vault_cred_type_t type)
{
    switch (type) {
    case CUPOLAS_VAULT_CRED_PASSWORD:
        return "password";
    case CUPOLAS_VAULT_CRED_TOKEN:
        return "token";
    case CUPOLAS_VAULT_CRED_KEY:
        return "key";
    case CUPOLAS_VAULT_CRED_CERTIFICATE:
        return "certificate";
    case CUPOLAS_VAULT_CRED_SECRET:
        return "secret";
    case CUPOLAS_VAULT_CRED_NOTE:
        return "note";
    default:
        return "unknown";
    }
}

const char *cupolas_vault_operation_string(cupolas_vault_operation_t op)
{
    switch (op) {
    case CUPOLAS_VAULT_OP_READ:
        return "read";
    case CUPOLAS_VAULT_OP_WRITE:
        return "write";
    case CUPOLAS_VAULT_OP_DELETE:
        return "delete";
    case CUPOLAS_VAULT_OP_EXPORT:
        return "export";
    default:
        return "unknown";
    }
}

static int vrand_bytes(unsigned char *buf, size_t len)
{
    if (!buf || len == 0) {
        return -1;
    }
#ifdef CUPOLAS_USE_OPENSSL
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
#else
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return -1;
    }
    size_t got = fread(buf, 1, len, urandom);
    fclose(urandom);
    return got == len ? 0 : -1;
#endif
}

/* 拒绝采样：避免 `byte % len` 的取模偏置，并保证字符表尾段可达。
 * 旧实现 256 % 66 == 58，特殊字符区（下标 62..65）永远取不到。 */
static int vrand_below(size_t bound, size_t *out)
{
    unsigned char b;
    unsigned limit;

    if (!out || bound == 0 || bound > 256) {
        return -1;
    }
    limit = (unsigned)(256 - (256 % bound));
    do {
        if (vrand_bytes(&b, 1) != 0) {
            return -1;
        }
    } while ((unsigned)b >= limit);
    *out = (size_t)b % bound;
    return 0;
}

int cupolas_vault_generate_password(char *password_out, size_t length)
{
    static const char *const classes[] = {"abcdefghijklmnopqrstuvwxyz",
                                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                                          "0123456789",
                                          "!@#$%^&*"};
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const size_t nclass = sizeof(classes) / sizeof(classes[0]);
    size_t n, i, j, idx;
    char tmp;

    if (!password_out || length < 8) {
        return AIRY_ERR_UNKNOWN;
    }
    n = length - 1;

    /* 每类先占一席，保证混合字符构成；其余位取全集，末位整体洗牌消除位置相关。 */
    for (i = 0; i < nclass; i++) {
        if (vrand_below(strlen(classes[i]), &idx) != 0) {
            password_out[0] = '\0';
            return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
        }
        password_out[i] = classes[i][idx];
    }
    for (; i < n; i++) {
        if (vrand_below(sizeof(charset) - 1, &idx) != 0) {
            password_out[0] = '\0';
            return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
        }
        password_out[i] = charset[idx];
    }
    for (i = n; i > 1; i--) {
        if (vrand_below(i, &j) != 0) {
            password_out[0] = '\0';
            return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
        }
        tmp = password_out[i - 1];
        password_out[i - 1] = password_out[j];
        password_out[j] = tmp;
    }
    password_out[n] = '\0';
    return 0;
}

int cupolas_vault_generate_keypair(char *public_key_out, size_t *pub_len, char *private_key_out,
                                   size_t *priv_len)
{
    if (!public_key_out || !pub_len || !private_key_out || !priv_len) {
        return AIRY_ERR_UNKNOWN;
    }

#ifdef CUPOLAS_USE_OPENSSL
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        return cupolas_ERR_INVALID_PARAM;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return cupolas_ERR_INVALID_PARAM;
    }
    EVP_PKEY_CTX_free(ctx);

    BIO *pub_bio = BIO_new(BIO_s_mem());
    BIO *priv_bio = BIO_new(BIO_s_mem());
    if (!pub_bio || !priv_bio) {
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        return cupolas_ERR_INVALID_PARAM;
    }

    if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1 ||
        PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        return cupolas_ERR_INVALID_PARAM;
    }

    int pub_read = BIO_read(pub_bio, public_key_out, (int)*pub_len);
    int priv_read = BIO_read(priv_bio, private_key_out, (int)*priv_len);
    if (pub_read <= 0 || priv_read <= 0) {
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        return cupolas_ERR_INVALID_PARAM;
    }
    *pub_len = (size_t)pub_read;
    *priv_len = (size_t)priv_read;

    BIO_free(pub_bio);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);

    return 0;

#else
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif
}
