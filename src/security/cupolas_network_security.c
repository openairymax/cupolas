// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

#include "cupolas.h"
/*
 *
 * cupolas_network_security.c - Network Security: TLS Hardening and Traffic Implementation
 */

#include <ctype.h>

/**
 * @file cupolas_network_security.c
 * @brief Network Security - TLS 加固与生命周期域
 *
 * 本文件保留网络安全模块的入口与核心状态机：初始化/清理/配置查询、
 * TLS 版本与证书校验、密码套件策略及版本字符串转换。
 * @author SPHARX Ltd. - Airymax Team
 * @date 2026
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

cupolas_net_security_state_t g_net_security;

void cupolas_free_filter_rule(cupolas_net_filter_rule_t *rule)
{
    if (!rule)
        return;
    AIRY_FREE(rule->rule_id);
    AIRY_FREE(rule->description);
    AIRY_FREE(rule->src_ip_pattern);
    AIRY_FREE(rule->dst_ip_pattern);
    AIRY_FREE(rule->host_pattern);
    AIRY_FREE(rule->url_pattern);
    __builtin_memset(rule, 0, sizeof(*rule));
}

void cupolas_free_connection_info(cupolas_connection_info_t *info)
{
    if (!info)
        return;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"
    AIRY_FREE(info->local_ip);
    AIRY_FREE(info->remote_ip);
    AIRY_FREE(info->hostname);
    AIRY_FREE(info->cipher_suite);
#pragma GCC diagnostic pop
    __builtin_memset(info, 0, sizeof(*info));
}

int cupolas_net_security_init(const cupolas_tls_config_t *manager)
{
    if (g_net_security.initialized)
        return 0;

    __builtin_memset(&g_net_security, 0, sizeof(g_net_security));

    CUPOLAS_MUTEX_INIT(&g_net_security.lock);
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_net_security.ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_net_security.ssl_ctx) {
        return AIRY_ERR_UNKNOWN;
    }

    if (manager) {
        g_net_security.manager = *manager;
    } else {
        g_net_security.manager.tls.min_version = CUPOLAS_TLS_1_2;
        g_net_security.manager.tls.max_version = CUPOLAS_TLS_1_3;
        g_net_security.manager.verify_mode = CUPOLAS_CERT_REQUIRED;
        g_net_security.manager.http.enforce_https = true;
        g_net_security.manager.http.hsts_enabled = true;
        g_net_security.manager.http.hsts_max_age = 31536000;
        g_net_security.manager.dns.enable_dnssec = true;
        g_net_security.manager.enable_logging = true;
        g_net_security.manager.enable_audit = true;
    }

    SSL_CTX_set_min_proto_version(g_net_security.ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_net_security.ssl_ctx, TLS1_3_VERSION);

    g_net_security.initialized = 1;
    return 0;
}

void cupolas_net_security_cleanup(void)
{
    if (!g_net_security.initialized)
        return;

    for (size_t i = 0; i < g_net_security.filter_rule_count; i++) {
        cupolas_free_filter_rule(&g_net_security.filter_rules[i].rule);
    }

    for (size_t i = 0; i < g_net_security.connection_count; i++) {
        cupolas_free_connection_info(&g_net_security.connections[i]);
    }

    if (g_net_security.ssl_ctx) {
        SSL_CTX_free(g_net_security.ssl_ctx);
    }

    EVP_cleanup();
    ERR_free_strings();

    CUPOLAS_MUTEX_DESTROY(&g_net_security.lock);
#ifdef _WIN32
    WSACleanup();
#endif

    __builtin_memset(&g_net_security, 0, sizeof(g_net_security));
}

int cupolas_net_security_get_config(cupolas_tls_config_t *manager)
{
    if (!manager)
        return AIRY_ERR_UNKNOWN;
    *manager = g_net_security.manager;
    return 0;
}

int cupolas_tls_configure(const cupolas_tls_config_t *manager)
{
    if (!manager)
        return AIRY_ERR_UNKNOWN;

    g_net_security.manager = *manager;

    if (g_net_security.ssl_ctx) {
        int min_ver = TLS1_2_VERSION;
        int max_ver = TLS1_3_VERSION;

        switch (manager->min_version) {
        case CUPOLAS_TLS_AUTO:
            min_ver = TLS1_2_VERSION;
            break;
        case CUPOLAS_TLS_1_2:
            min_ver = TLS1_2_VERSION;
            break;
        case CUPOLAS_TLS_1_3:
            min_ver = TLS1_3_VERSION;
            break;
        }

        switch (manager->max_version) {
        case CUPOLAS_TLS_AUTO:
            max_ver = TLS1_3_VERSION;
            break;
        case CUPOLAS_TLS_1_2:
            max_ver = TLS1_2_VERSION;
            break;
        case CUPOLAS_TLS_1_3:
            max_ver = TLS1_3_VERSION;
            break;
        }

        SSL_CTX_set_min_proto_version(g_net_security.ssl_ctx, min_ver);
        SSL_CTX_set_max_proto_version(g_net_security.ssl_ctx, max_ver);

        if (manager->ca_bundle_path) {
            SSL_CTX_load_verify_locations(g_net_security.ssl_ctx, manager->ca_bundle_path, NULL);
        }

        if (manager->client_cert_path && manager->client_key_path) {
            SSL_CTX_use_certificate_file(g_net_security.ssl_ctx, manager->client_cert_path,
                                         SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(g_net_security.ssl_ctx, manager->client_key_path,
                                        SSL_FILETYPE_PEM);
        }
    }

    return 0;
}

int cupolas_tls_verify_cert(const char *cert_path, const char *hostname,
                            cupolas_cert_mode_t *result)
{
    if (!cert_path || !result)
        return AIRY_ERR_UNKNOWN;

    *result = CUPOLAS_CERT_NONE;

    FILE *f = fopen(cert_path, "r");
    if (!f) {
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    if (!cert) {
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);

    time_t now = time(NULL);
    int before_cmp = X509_cmp_time(not_before, &now);
    int after_cmp = X509_cmp_time(not_after, &now);

    if (before_cmp > 0) {
        *result = CUPOLAS_CERT_REQUIRED;
        X509_free(cert);
        return 0;
    }

    if (after_cmp < 0) {
        *result = CUPOLAS_CERT_REQUIRED;
        X509_free(cert);
        return 0;
    }

    if (hostname) {
        char *hostname_dup = cupolas_strdup(hostname);
        int match = X509_check_host(cert, hostname_dup, strlen(hostname_dup), 0, NULL);
        AIRY_FREE(hostname_dup);

        if (match != 1) {
            *result = CUPOLAS_CERT_REQUIRED;
            X509_free(cert);
            return 0;
        }
    }

    X509_free(cert);
    return 0;
}

int cupolas_tls_verify_cert_chain(const char *cert_chain, size_t chain_len,
                                  cupolas_cert_mode_t *result)
{
    if (!cert_chain || !result)
        return AIRY_ERR_UNKNOWN;

    *result = CUPOLAS_CERT_NONE;

    BIO *bio = BIO_new_mem_buf(cert_chain, (int)chain_len);
    if (!bio) {
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    STACK_OF(X509) *certs = sk_X509_new_null();
    X509 *cert = NULL;

    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(certs, cert);
    }

    BIO_free(bio);

    if (sk_X509_num(certs) == 0) {
        *result = CUPOLAS_CERT_REQUIRED;
        sk_X509_free(certs);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return AIRY_ERR_UNKNOWN;
    }

    X509_STORE_CTX_init(ctx, store, sk_X509_value(certs, 0), certs);

    int verify_result = X509_verify_cert(ctx);
    if (verify_result != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        switch (err) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        case X509_V_ERR_CERT_REVOKED:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        default:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        }
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_pop_free(certs, X509_free);

    return 0;
}

int cupolas_tls_check_connection(const char *hostname, uint16_t port, cupolas_cert_mode_t *result)
{
    if (!hostname || !result)
        return AIRY_ERR_UNKNOWN;

    *result = CUPOLAS_CERT_NONE;

    struct hostent *host = gethostbyname(hostname);
    if (!host) {
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    struct sockaddr_in addr;
    __builtin_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    /* gethostbyname 可能返回 IPv6 记录（h_length=16），sin_addr 仅 4 字节，
     * 直接整长拷贝会栈越界写。仅接受 AF_INET 且长度匹配的记录。 */
    if (host->h_addrtype != AF_INET || host->h_length > (int)sizeof(addr.sin_addr)) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }
    __builtin_memcpy(&addr.sin_addr, host->h_addr, host->h_length);

    int connect_result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_result != 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    SSL *ssl = SSL_new(g_net_security.ssl_ctx);
    if (!ssl) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        *result = CUPOLAS_CERT_REQUIRED;
        return AIRY_ERR_UNKNOWN;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, hostname);

    int ssl_result = SSL_connect(ssl);
    if (ssl_result != 1) {
        int err = SSL_get_error(ssl, ssl_result);
        switch (err) {
        case SSL_ERROR_SSL:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        case SSL_ERROR_SYSCALL:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        default:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        }
        SSL_free(ssl);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return 0;
    }

    long verify_result_long = SSL_get_verify_result(ssl);
    if (verify_result_long != X509_V_OK) {
        switch (verify_result_long) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        case X509_V_ERR_CERT_REVOKED:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        default:
            *result = CUPOLAS_CERT_REQUIRED;
            break;
        }
    }

    SSL_free(ssl);
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return 0;
}

int cupolas_tls_get_cipher_suites(char ***suites, size_t *count)
{
    if (!suites || !count)
        return AIRY_ERR_UNKNOWN;

    static const char *default_suites[] = {"TLS_AES_256_GCM_SHA384",
                                           "TLS_CHACHA20_POLY1305_SHA256",
                                           "TLS_AES_128_GCM_SHA256",
                                           "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                           "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                           "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                           "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"};

    *count = sizeof(default_suites) / sizeof(default_suites[0]);
    SAFE_MALLOC_ARRAY(*suites, *count, sizeof(char *));
    if (!*suites)
        return AIRY_ERR_UNKNOWN;

    for (size_t i = 0; i < *count; i++) {
        (*suites)[i] = cupolas_strdup(default_suites[i]);
    }

    return 0;
}

int cupolas_tls_is_cipher_secure(const char *suite)
{
    if (!suite)
        return 0;

    const char *secure_suites[] = {"TLS_AES_256_GCM_SHA384",
                                   "TLS_CHACHA20_POLY1305_SHA256",
                                   "TLS_AES_128_GCM_SHA256",
                                   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                   "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                                   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"};

    for (size_t i = 0; i < sizeof(secure_suites) / sizeof(secure_suites[0]); i++) {
        if (strcmp(suite, secure_suites[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

const char *cupolas_tls_version_string(cupolas_tls_version_t version)
{
    switch (version) {
    case CUPOLAS_TLS_AUTO:
        return "Auto";
    case CUPOLAS_TLS_1_2:
        return "TLS 1.2";
    case CUPOLAS_TLS_1_3:
        return "TLS 1.3";
    default:
        return "Unknown";
    }
}

const char *cupolas_protocol_string(cupolas_proto_t protocol)
{
    switch (protocol) {
    case CUPOLAS_PROTO_ANY:
        return "Any";
    case CUPOLAS_PROTO_TCP:
        return "TCP";
    case CUPOLAS_PROTO_UDP:
        return "UDP";
    case CUPOLAS_PROTO_ICMP:
        return "ICMP";
    default:
        return "Unknown";
    }
}

const char *cupolas_cert_result_string(cupolas_cert_mode_t result)
{
    switch (result) {
    case CUPOLAS_CERT_NONE:
        return "No validation";
    case CUPOLAS_CERT_OPTIONAL:
        return "Optional";
    case CUPOLAS_CERT_REQUIRED:
        return "Required";
    default:
        return "Unknown";
    }
}
