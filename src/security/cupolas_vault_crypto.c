// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_crypto.c
 * @brief Crypto utilities domain: type/operation string mapping and
 *        random passphrase / key-pair generation.
 */

#include "error.h"
#include "cupolas.h"
#include "cupolas_vault.h"
#include "cupolas_vault_internal.h"

#include "../platform/platform.h"
#include "atomic_compat.h"
#include "cupolas_error.h"
#include "logging.h"
#include "airy_memory.h"
#include "utils/cupolas_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CUPOLAS_USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#endif

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

int cupolas_vault_generate_password(char *password_out, size_t length)
{
    if (!password_out || length < 8) {
        return AIRY_ERR_UNKNOWN;
    }

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    size_t charset_len = strlen(charset);

#ifdef CUPOLAS_USE_OPENSSL
    for (size_t i = 0; i < length - 1; i++) {
        unsigned char c;
        if (RAND_bytes(&c, 1) != 1) {
            password_out[length - 1] = '\0';
            return cupolas_ERR_INVALID_PARAM;
        }
        password_out[i] = charset[c % charset_len];
    }
#else
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        for (size_t i = 0; i < length - 1; i++) {
            unsigned char c;
            if (fread(&c, 1, 1, urandom) != 1) {
                fclose(urandom);
                password_out[length - 1] = '\0';
                return cupolas_ERR_INVALID_PARAM;
            }
            password_out[i] = charset[c % charset_len];
        }
        fclose(urandom);
    } else {
        password_out[length - 1] = '\0';
        return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
    }
#endif

    password_out[length - 1] = '\0';
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
