// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_vault_io.c
 * @brief Import/export domain: encrypted vault export and import
 *        (AES-256-CBC container format).
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

int cupolas_vault_export(cupolas_vault_t *vault, const char *export_path, const char *password,
                         const char *agent_id)
{
    if (!vault || !export_path || !password) {
        return AIRY_ERR_UNKNOWN;
    }

    if (vault->is_locked) {
        return cupolas_ERR_INVALID_PARAM;
    }

#define VAULT_FWRITE(ptr, sz, cnt, fp)           \
    do {                                         \
        if (fwrite(ptr, sz, cnt, fp) != (cnt)) { \
            goto export_fail;                    \
        }                                        \
    } while (0)

#ifdef CUPOLAS_USE_OPENSSL
    FILE *f = fopen(export_path, "wb");
    if (!f) {
        return cupolas_ERR_NULL_POINTER;
    }

    uint8_t file_salt[SALT_SIZE] = {0};
    if (RAND_bytes(file_salt, SALT_SIZE) != 1) {
        fclose(f);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    uint8_t derived_key_iv[AES_KEY_SIZE + AES_IV_SIZE] = {0};

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), file_salt, SALT_SIZE, 100000, EVP_sha256(),
                          AES_KEY_SIZE + AES_IV_SIZE, derived_key_iv) != 1) {
        fclose(f);
        remove(export_path);
        return cupolas_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t *derived_key = derived_key_iv;
    uint8_t *derived_iv = derived_key_iv + AES_KEY_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(f);
        remove(export_path);
        return cupolas_ERR_NOT_FOUND;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, derived_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f);
        remove(export_path);
        return cupolas_ERR_ALREADY_EXISTS;
    }

    uint32_t magic = VAULT_MAGIC;
    uint32_t version = VAULT_VERSION;
    VAULT_FWRITE(&magic, sizeof(magic), 1, f);
    VAULT_FWRITE(&version, sizeof(version), 1, f);
    VAULT_FWRITE(file_salt, SALT_SIZE, 1, f);

    time_t now = time(NULL);
    VAULT_FWRITE(&now, sizeof(time_t), 1, f);

    if (agent_id) {
        size_t agent_len = strlen(agent_id);
        VAULT_FWRITE(&agent_len, sizeof(size_t), 1, f);
        VAULT_FWRITE(agent_id, 1, agent_len, f);
    } else {
        size_t zero = 0;
        VAULT_FWRITE(&zero, sizeof(size_t), 1, f);
    }

    uint32_t cred_count = (uint32_t)vault->entry_count;
    VAULT_FWRITE(&cred_count, sizeof(uint32_t), 1, f);

    for (size_t i = 0; i < vault->entry_count; i++) {
        credential_entry_t *entry = &vault->entries[i];

        size_t id_len = strlen(entry->cred_id);
        VAULT_FWRITE(&id_len, sizeof(size_t), 1, f);
        VAULT_FWRITE(entry->cred_id, 1, id_len, f);

        VAULT_FWRITE(&entry->type, sizeof(cupolas_vault_cred_type_t), 1, f);
        VAULT_FWRITE(&entry->encrypted_len, sizeof(size_t), 1, f);

        int out_len = 0;
        int final_len = 0;
        uint8_t *encrypted_buf = (uint8_t *)AIRY_MALLOC(entry->encrypted_len + AES_BLOCK_SIZE);
        if (!encrypted_buf || EVP_EncryptUpdate(ctx, encrypted_buf, &out_len, entry->encrypted_data,
                                                entry->encrypted_len) != 1) {
            AIRY_FREE(encrypted_buf);
            EVP_CIPHER_CTX_free(ctx);
            fclose(f);
            remove(export_path);
            return cupolas_ERR_TIMEOUT;
        }

        if (EVP_EncryptFinal_ex(ctx, encrypted_buf + out_len, &final_len) != 1) {
            AIRY_FREE(encrypted_buf);
            EVP_CIPHER_CTX_free(ctx);
            fclose(f);
            remove(export_path);
            return cupolas_ERR_NOT_SUPPORTED;
        }

        size_t total_encrypted = out_len + final_len;
        VAULT_FWRITE(&total_encrypted, sizeof(size_t), 1, f);
        VAULT_FWRITE(encrypted_buf, 1, total_encrypted, f);
        AIRY_FREE(encrypted_buf);

        VAULT_FWRITE(entry->iv, AES_IV_SIZE, 1, f);
        VAULT_FWRITE(entry->salt, SALT_SIZE, 1, f);

        VAULT_FWRITE(&entry->acl.count, sizeof(size_t), 1, f);
        for (size_t k = 0; k < entry->acl.count; k++) {
            size_t agent_id_len =
                entry->acl.entries[k].agent_id ? strlen(entry->acl.entries[k].agent_id) : 0;
            VAULT_FWRITE(&agent_id_len, sizeof(size_t), 1, f);
            if (agent_id_len > 0) {
                VAULT_FWRITE(entry->acl.entries[k].agent_id, 1, agent_id_len, f);
            }
            VAULT_FWRITE(&entry->acl.entries[k].operations, sizeof(uint32_t), 1, f);
            VAULT_FWRITE(&entry->acl.entries[k].expires_at, sizeof(uint64_t), 1, f);
            VAULT_FWRITE(&entry->acl.entries[k].access_count, sizeof(uint32_t), 1, f);
            VAULT_FWRITE(&entry->acl.entries[k].max_access_count, sizeof(uint32_t), 1, f);
        }

        {
            const char *meta_fields[] = {entry->metadata.cred_id, entry->metadata.description,
                                         entry->metadata.service, entry->metadata.account};
            for (int m = 0; m < 4; m++) {
                size_t field_len = meta_fields[m] ? strlen(meta_fields[m]) : 0;
                VAULT_FWRITE(&field_len, sizeof(size_t), 1, f);
                if (field_len > 0) {
                    VAULT_FWRITE(meta_fields[m], 1, field_len, f);
                }
            }
            VAULT_FWRITE(&entry->metadata.type, sizeof(cupolas_vault_cred_type_t), 1, f);
            VAULT_FWRITE(&entry->metadata.created_at, sizeof(uint64_t), 1, f);
            VAULT_FWRITE(&entry->metadata.updated_at, sizeof(uint64_t), 1, f);
            VAULT_FWRITE(&entry->metadata.expires_at, sizeof(uint64_t), 1, f);
            VAULT_FWRITE(&entry->metadata.is_accessible, sizeof(bool), 1, f);
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(f);

    if (vault->config.enable_audit) {
        LOG_INFO("[VAULT] Export completed: %zu credentials to %s", vault->entry_count,
                 export_path);
    }

    return 0;

export_fail:
    EVP_CIPHER_CTX_free(ctx);
    fclose(f);
    remove(export_path);
    return cupolas_ERR_UNKNOWN;

#else
    (void)agent_id;
    return cupolas_VAULT_ERR_CRYPTO_UNAVAILABLE;
#endif
}

int cupolas_vault_import(cupolas_vault_t *vault, const char *import_path, const char *password,
                         const char *agent_id)
{
    if (!vault || !import_path || !password) {
        return AIRY_ERR_UNKNOWN;
    }

    if (vault->is_locked) {
        return cupolas_ERR_INVALID_PARAM;
    }

#ifdef CUPOLAS_USE_OPENSSL
    FILE *f = fopen(import_path, "rb");
    if (!f) {
        return cupolas_ERR_NULL_POINTER;
    }

    uint32_t magic = 0;
    if (fread(&magic, sizeof(uint32_t), 1, f) != 1 || magic != VAULT_MAGIC) {
        fclose(f);
        return cupolas_ERR_OUT_OF_MEMORY;
    }

    uint32_t version = 0;
    if (fread(&version, sizeof(uint32_t), 1, f) != 1 || version > VAULT_VERSION) {
        fclose(f);
        return cupolas_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t file_salt[SALT_SIZE] = {0};
    if (fread(file_salt, SALT_SIZE, 1, f) != 1) {
        fclose(f);
        return cupolas_ERR_NOT_FOUND;
    }

    time_t export_time = 0;
    if (fread(&export_time, sizeof(time_t), 1, f) != 1) {
        fclose(f);
        return cupolas_ERR_NOT_FOUND;
    }

    size_t agent_len = 0;
    if (fread(&agent_len, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        return cupolas_ERR_NOT_FOUND;
    }
    if (agent_len > 0 && agent_len < 65536) {
        char *file_agent_id = (char *)AIRY_MALLOC(agent_len + 1);
        if (file_agent_id) {
            if (fread(file_agent_id, 1, agent_len, f) != agent_len) {
                AIRY_FREE(file_agent_id);
                fclose(f);
                return cupolas_ERR_NOT_FOUND;
            }
            file_agent_id[agent_len] = '\0';
            AIRY_FREE(file_agent_id);
        } else {
            fseek(f, agent_len, SEEK_CUR);
        }
    } else if (agent_len >= 65536) {
        fclose(f);
        return cupolas_ERR_NOT_FOUND;
    }

    uint32_t cred_count = 0;
    if (fread(&cred_count, sizeof(uint32_t), 1, f) != 1) {
        fclose(f);
        return cupolas_ERR_ALREADY_EXISTS;
    }

    uint8_t derived_key_iv[AES_KEY_SIZE + AES_IV_SIZE] = {0};

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), file_salt, SALT_SIZE, 100000, EVP_sha256(),
                          AES_KEY_SIZE + AES_IV_SIZE, derived_key_iv) != 1) {
        fclose(f);
        return cupolas_ERR_TIMEOUT;
    }

    uint8_t *derived_key = derived_key_iv;
    uint8_t *derived_iv = derived_key_iv + AES_KEY_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(f);
        return cupolas_ERR_NOT_SUPPORTED;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, derived_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f);
        return cupolas_ERR_UNKNOWN;
    }

    size_t imported = 0;

    for (uint32_t i = 0; i < cred_count; i++) {
        size_t id_len = 0;
        if (fread(&id_len, sizeof(size_t), 1, f) != 1)
            break;

        char *cred_id = (char *)AIRY_MALLOC(id_len + 1);
        if (!cred_id || fread(cred_id, 1, id_len, f) != 1) {
            AIRY_FREE(cred_id);
            break;
        }
        cred_id[id_len] = '\0';

        cupolas_vault_cred_type_t type;
        if (fread(&type, sizeof(cupolas_vault_cred_type_t), 1, f) != 1) {
            AIRY_FREE(cred_id);
            break;
        }

        size_t enc_len = 0;
        if (fread(&enc_len, sizeof(size_t), 1, f) != 1) {
            AIRY_FREE(cred_id);
            break;
        }

        uint8_t *enc_data = (uint8_t *)AIRY_MALLOC(enc_len);
        if (!enc_data || fread(enc_data, 1, enc_len, f) != enc_len) {
            AIRY_FREE(cred_id);
            cred_id = NULL;
            AIRY_FREE(enc_data);
            enc_data = NULL;
            break;
        }

        int out_len = 0;
        int final_len = 0;
        uint8_t *decrypted = (uint8_t *)AIRY_MALLOC(enc_len + AES_BLOCK_SIZE);
        if (!decrypted || EVP_DecryptUpdate(ctx, decrypted, &out_len, enc_data, enc_len) != 1 ||
            EVP_DecryptFinal_ex(ctx, decrypted + out_len, &final_len) != 1) {
            AIRY_FREE(cred_id);
            cred_id = NULL;
            AIRY_FREE(enc_data);
            enc_data = NULL;
            AIRY_FREE(decrypted);
            decrypted = NULL;
            continue;
        }

        size_t total_decrypted = out_len + final_len;

        if (vault->entry_count >= vault->entry_capacity) {
            size_t new_cap = vault->entry_capacity * 2;
            credential_entry_t *new_entries =
                (credential_entry_t *)AIRY_REALLOC(vault->entries,
                                                   new_cap * sizeof(credential_entry_t));
            if (!new_entries) {
                AIRY_FREE(cred_id);
                cred_id = NULL;
                AIRY_FREE(enc_data);
                enc_data = NULL;
                AIRY_FREE(decrypted);
                decrypted = NULL;
                continue;
            }
            vault->entries = new_entries;
            vault->entry_capacity = new_cap;
        }

        credential_entry_t *entry = &vault->entries[vault->entry_count];
        __builtin_memset(entry, 0, sizeof(credential_entry_t));
        entry->cred_id = cred_id;
        entry->type = type;
        entry->encrypted_data = (uint8_t *)AIRY_MALLOC(total_decrypted);
        if (entry->encrypted_data) {
            __builtin_memcpy(entry->encrypted_data, decrypted, total_decrypted);
            entry->encrypted_len = total_decrypted;
        } else {
            entry->encrypted_data = NULL;
            entry->encrypted_len = 0;
        }

        if (fread(entry->iv, AES_IV_SIZE, 1, f) != 1 || fread(entry->salt, SALT_SIZE, 1, f) != 1) {
            AIRY_FREE(entry->encrypted_data);
            entry->encrypted_data = NULL;
            entry->encrypted_len = 0;
            AIRY_FREE(enc_data);
            enc_data = NULL;
            AIRY_FREE(decrypted);
            decrypted = NULL;
            continue;
        }

        {
            size_t acl_count = 0;
            if (fread(&acl_count, sizeof(size_t), 1, f) != 1 ||
                acl_count > MAX_ACL_ENTRIES_PER_CREDENTIAL) {
                AIRY_FREE(entry->encrypted_data);
                entry->encrypted_data = NULL;
                entry->encrypted_len = 0;
                AIRY_FREE(enc_data);
                enc_data = NULL;
                AIRY_FREE(decrypted);
                decrypted = NULL;
                continue;
            }
            entry->acl.count = acl_count;
            if (acl_count > 0) {
                entry->acl.entries =
                    (cupolas_vault_acl_entry_t *)AIRY_CALLOC(acl_count,
                                                             sizeof(cupolas_vault_acl_entry_t));
                if (!entry->acl.entries) {
                    continue;
                }
                for (size_t k = 0; k < acl_count; k++) {
                    size_t agent_id_len = 0;
                    if (fread(&agent_id_len, sizeof(size_t), 1, f) != 1)
                        break;
                    if (agent_id_len > 0 && agent_id_len < 65536) {
                        entry->acl.entries[k].agent_id = (char *)AIRY_MALLOC(agent_id_len + 1);
                        if (entry->acl.entries[k].agent_id) {
                            if (fread(entry->acl.entries[k].agent_id, 1, agent_id_len, f) !=
                                agent_id_len) {
                                AIRY_FREE(entry->acl.entries[k].agent_id);
                                entry->acl.entries[k].agent_id = NULL;
                            }
                            entry->acl.entries[k].agent_id[agent_id_len] = '\0';
                        }
                    }
                    {
                        size_t _fr;
                        _fr = fread(&entry->acl.entries[k].operations, sizeof(uint32_t), 1, f);
                        if (_fr < 1) {
                            break;
                        }
                    }
                    {
                        size_t _fr;
                        _fr = fread(&entry->acl.entries[k].expires_at, sizeof(uint64_t), 1, f);
                        if (_fr < 1) {
                            break;
                        }
                    }
                    {
                        size_t _fr;
                        _fr = fread(&entry->acl.entries[k].access_count, sizeof(uint32_t), 1, f);
                        if (_fr < 1) {
                            break;
                        }
                    }
                    {
                        size_t _fr;
                        _fr =
                            fread(&entry->acl.entries[k].max_access_count, sizeof(uint32_t), 1, f);
                        if (_fr < 1) {
                            break;
                        }
                    }
                }
            }
        }

        {
            __builtin_memset(&entry->metadata, 0, sizeof(entry->metadata));
            char *meta_ptrs[4] = {NULL, NULL, NULL, NULL};
            for (int m = 0; m < 4; m++) {
                size_t field_len = 0;
                if (fread(&field_len, sizeof(size_t), 1, f) != 1)
                    continue;
                if (field_len > 0 && field_len < 65536) {
                    meta_ptrs[m] = (char *)AIRY_MALLOC(field_len + 1);
                    if (meta_ptrs[m]) {
                        if (fread(meta_ptrs[m], 1, field_len, f) == field_len) {
                            meta_ptrs[m][field_len] = '\0';
                        } else {
                            AIRY_FREE(meta_ptrs[m]);
                            meta_ptrs[m] = NULL;
                        }
                    }
                }
            }
            entry->metadata.cred_id = meta_ptrs[0];
            entry->metadata.description = meta_ptrs[1];
            entry->metadata.service = meta_ptrs[2];
            entry->metadata.account = meta_ptrs[3];
            {
                size_t _fr;
                _fr = fread(&entry->metadata.type, sizeof(cupolas_vault_cred_type_t), 1, f);
                if (_fr < 1) {
                    break;
                }
            }
            {
                size_t _fr;
                _fr = fread(&entry->metadata.created_at, sizeof(uint64_t), 1, f);
                if (_fr < 1) {
                    break;
                }
            }
            {
                size_t _fr;
                _fr = fread(&entry->metadata.updated_at, sizeof(uint64_t), 1, f);
                if (_fr < 1) {
                    break;
                }
            }
            {
                size_t _fr;
                _fr = fread(&entry->metadata.expires_at, sizeof(uint64_t), 1, f);
                if (_fr < 1) {
                    break;
                }
            }
            {
                size_t _fr;
                _fr = fread(&entry->metadata.is_accessible, sizeof(bool), 1, f);
                if (_fr < 1) {
                    break;
                }
            }
        }

        vault->entry_count++;
        imported++;

        AIRY_FREE(enc_data);
        enc_data = NULL;
        AIRY_FREE(decrypted);
        decrypted = NULL;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(f);

    if (vault->config.enable_audit) {
        LOG_INFO("[VAULT] Import completed: %zu credentials from %s", imported, import_path);
    }

    return (int)imported;
#else
    if (!password || !agent_id)
        return cupolas_VAULT_ERR_INVALID;

    FILE *f = fopen(import_path, "r");
    if (!f)
        return cupolas_ERR_NULL_POINTER;

    char line[1024];
    size_t imported = 0;
    bool in_entry = false;
    char current_id[256] = {0};

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            if (in_entry && current_id[0]) {
                if (vault->entry_count < vault->entry_capacity) {
                    credential_entry_t *entry = &vault->entries[vault->entry_count];
                    entry->cred_id = AIRY_STRDUP(current_id);
                    entry->type = 0;
                    entry->encrypted_data = NULL;
                    entry->encrypted_len = 0;
                    __builtin_memset(&entry->acl, 0, sizeof(entry->acl));
                    __builtin_memset(&entry->metadata, 0, sizeof(entry->metadata));
                    vault->entry_count++;
                    imported++;
                }
            }
            AIRY_STRNCPY_TERM(current_id, line + 1, sizeof(current_id));
            in_entry = true;
        }
    }

    if (in_entry && current_id[0] && vault->entry_count < vault->entry_capacity) {
        credential_entry_t *entry = &vault->entries[vault->entry_count];
        entry->cred_id = AIRY_STRDUP(current_id);
        entry->type = 0;
        entry->encrypted_data = NULL;
        entry->encrypted_len = 0;
        __builtin_memset(&entry->acl, 0, sizeof(entry->acl));
        __builtin_memset(&entry->metadata, 0, sizeof(entry->metadata));
        vault->entry_count++;
        imported++;
    }

    fclose(f);
    return (int)imported;
#endif
}
