/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 *
 * cupolas_network_security.h - Network Security: TLS, Firewall, and Network Access Control
 */

#ifndef CUPOLAS_NETWORK_SECURITY_H
#define CUPOLAS_NETWORK_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TLS version enumeration
 *
 * Design principles:
 * - Strong encryption: Only modern TLS versions
 * - Perfect forward secrecy: Ephemeral key exchange
 * - Certificate validation: Strict chain verification
 * - Cipher suite control: Only strong ciphers allowed
 */
typedef enum {
    CUPOLAS_TLS_AUTO = 0, /**< Auto-negotiate best version */
    CUPOLAS_TLS_1_2 = 1, /**< TLS 1.2 */
    CUPOLAS_TLS_1_3 = 2 /**< TLS 1.3 */
} cupolas_tls_version_t;

/**
 * @brief Certificate validation mode
 */
typedef enum {
    CUPOLAS_CERT_NONE = 0, /**< No validation */
    CUPOLAS_CERT_OPTIONAL, /**< Optional client cert */
    CUPOLAS_CERT_REQUIRED /**< Required client cert */
} cupolas_cert_mode_t;

/**
 * @brief Firewall action
 */
typedef enum {
    CUPOLAS_FW_ALLOW = 0, /**< Allow connection */
    CUPOLAS_FW_DENY, /**< Deny connection */
    CUPOLAS_FW_LOG, /**< Log only */
    CUPOLAS_FW_RATE_LIMIT /**< Rate limit */
} cupolas_fw_action_t;

/**
 * @brief Network protocol
 */
typedef enum {
    CUPOLAS_PROTO_ANY = 0, /**< Any protocol */
    CUPOLAS_PROTO_TCP, /**< TCP */
    CUPOLAS_PROTO_UDP, /**< UDP */
    CUPOLAS_PROTO_ICMP /**< ICMP */
} cupolas_proto_t;

/**
 * @brief Connection direction
 */
typedef enum {
    CUPOLAS_DIR_ANY = 0, /**< Any direction */
    CUPOLAS_DIR_INBOUND, /**< Inbound */
    CUPOLAS_DIR_OUTBOUND /**< Outbound */
} cupolas_direction_t;

/**
 * @brief TLS configuration
 */
typedef struct {
    cupolas_tls_version_t min_version; /**< Minimum TLS version */
    cupolas_tls_version_t max_version; /**< Maximum TLS version */

    char **cipher_suites; /**< Allowed cipher suites */
    size_t cipher_count; /**< Number of ciphers */

    const char *ca_file; /**< CA certificate file */
    const char *ca_path; /**< CA certificate path */
    const char *cert_file; /**< Certificate file */
    const char *key_file; /**< Private key file */

    cupolas_cert_mode_t verify_mode; /**< Verification mode */
    bool verify_hostname; /**< Verify hostname */
    bool verify_depth; /**< Verification depth */

    bool enable_ocsp_stapling; /**< Enable OCSP stapling */
    bool enable_sct; /**< Enable SCT */
    bool enable_session_tickets; /**< Enable session tickets */
    uint32_t session_cache_size; /**< Session cache size */
    bool enable_logging; /**< Enable logging */
    bool enable_audit; /**< Enable audit */
    char *ca_bundle_path; /**< CA bundle path */
    char *client_cert_path; /**< Client certificate path */
    char *client_key_path; /**< Client key path */
    struct {
        cupolas_tls_version_t min_version;
        cupolas_tls_version_t max_version;
    } tls;

    uint32_t handshake_timeout_ms; /**< Handshake timeout */
    uint32_t read_timeout_ms; /**< Read timeout */
    uint32_t write_timeout_ms; /**< Write timeout */

    bool enable_ids; /**< Enable IDS */
    struct {
        bool enforce_https;
        bool enable_dnssec;
        char dns_server[64];
        char **blocked_domains;
        size_t blocked_count;
        char **allowed_domains;
        size_t domain_count;
        size_t max_url_length;
        size_t max_body_size;
        char **allowed_methods;
        size_t method_count;
        char **forbidden_headers;
        size_t forbidden_count;
        bool hsts_enabled;
        uint32_t hsts_max_age;
    } http;
    struct {
        bool enable_dnssec;
        char upstream_server[64];
        char **blocked_domains;
        size_t blocked_count;
        char **allowed_domains;
        size_t domain_count;
    } dns;
} cupolas_tls_config_t;

/**
 * @brief Firewall rule structure
 */
typedef struct {
    char *rule_id; /**< Rule identifier */
    cupolas_proto_t protocol; /**< Protocol */
    cupolas_direction_t direction; /**< Direction */

    char *src_ip; /**< Source IP/CIDR */
    char *src_port; /**< Source port range */
    char *dst_ip; /**< Destination IP/CIDR */
    char *dst_port; /**< Destination port range */

    cupolas_fw_action_t action; /**< Action */
    bool log; /**< Enable logging */
    uint32_t rate_limit; /**< Rate limit (connections/sec) */

    uint64_t valid_from; /**< Valid from timestamp */
    uint64_t valid_until; /**< Valid until timestamp */

    char *description; /**< Rule description */
    char *src_ip_pattern; /**< Source IP pattern */
    char *dst_ip_pattern; /**< Destination IP pattern */
    char *host_pattern; /**< Host pattern */
    char *url_pattern; /**< URL pattern */
    bool enabled; /**< Rule enabled */
    uint16_t dst_port_start; /**< Destination port range start */
    uint16_t dst_port_end; /**< Destination port range end */
    uint16_t src_port_start; /**< Source port range start */
    uint16_t src_port_end; /**< Source port range end */
    int priority; /**< Rule priority */
    uint32_t burst_limit; /**< Burst limit for rate limiting */
} cupolas_fw_rule_t;

typedef struct {
    char local_ip[64];
    uint16_t local_port;
    char remote_ip[64];
    uint16_t remote_port;
    cupolas_proto_t protocol;
    bool is_encrypted;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t connect_time;
    char hostname[256];
    char cipher_suite[128];
    struct {
        bool enforce_https;
    } http;
} cupolas_connection_info_t;

/**
 * @brief Firewall configuration
 */
typedef struct {
    bool enable; /**< Enable firewall */
    cupolas_fw_action_t default_inbound; /**< Default inbound action */
    cupolas_fw_action_t default_outbound; /**< Default outbound action */

    cupolas_fw_rule_t *rules; /**< Rules array */
    size_t rule_count; /**< Number of rules */

    bool enable_logging; /**< Enable logging */
    bool enable_rate_limiting; /**< Enable rate limiting */

    uint32_t max_connections; /**< Maximum connections */
    uint32_t connection_timeout_ms; /**< Connection timeout */
} cupolas_firewall_config_t;

/**
 * @brief Network security statistics
 */
typedef struct {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t tls_handshakes;
    uint64_t tls_failures;
    uint64_t firewall_blocks;
    uint64_t rate_limit_hits;
    uint64_t cert_errors;
    uint64_t hostname_mismatches;
    uint64_t dns_queries;
    uint64_t dns_blocked;
    uint64_t http_requests;
    uint64_t https_requests;
    uint64_t plaintext_blocked;
    uint64_t blocked_connections;
} cupolas_net_stats_t;

typedef cupolas_fw_rule_t cupolas_net_filter_rule_t;
typedef struct {
    bool enable_ids;
    cupolas_tls_config_t manager;
} cupolas_net_security_config_t;
typedef struct {
    bool enable_ids;
} cupolas_ids_config_t;
typedef struct {
    bool enable_dnssec;
    char upstream_server[64];
} cupolas_dns_security_config_t;
typedef struct {
    bool enforce_https;
    size_t max_url_length;
    size_t max_body_size;
    char **allowed_methods;
    size_t method_count;
    char **forbidden_headers;
    size_t forbidden_count;
} cupolas_http_security_config_t;

/* ============================================================================
 * Public API (one-to-one with the cupolas_network_security.c implementation)
 *
 * Legacy note: the old-generation APIs (cupolas_network_security_init,
 * cupolas_tls_*, cupolas_firewall_*, cupolas_cert_* -- 30 in total) were
 * only declared in this header with no implementation, so any caller
 * would fail at link time. The declarations are now aligned with the
 * implemented cupolas_net_* API, eliminating the declaration/implementation
 * split.
 * ============================================================================ */

/**
 * @brief Initialize the network security module (default TLS 1.2-1.3,
 *        enforced HTTPS, DNSSEC)
 * @param[in] manager Configuration (NULL for secure defaults)
 * @return 0 on success, negative on failure
 */
int cupolas_net_security_init(const cupolas_tls_config_t *manager);

/**
 * @brief Shut down the network security module
 */
void cupolas_net_security_cleanup(void);

/**
 * @brief Read the current security configuration
 * @param[out] manager Configuration output
 * @return 0 on success, negative on failure
 */
int cupolas_net_security_get_config(cupolas_tls_config_t *manager);

/**
 * @brief Configure the TLS policy (version/cipher suites/verify mode)
 * @param[in] manager Configuration (NULL for secure defaults)
 * @return 0 on success, negative on failure
 */
int cupolas_tls_configure(const cupolas_tls_config_t *manager);

/**
 * @brief Verify that a certificate file (path) matches the hostname
 * @param[in] cert_path Certificate file path
 * @param[in] hostname  Expected hostname
 * @param[out] result   Verification result (cupolas_cert_mode_t)
 * @return 0 on success, negative on failure
 */
int cupolas_tls_verify_cert(const char *cert_path, const char *hostname,
                            cupolas_cert_mode_t *result);

/**
 * @brief Verify a certificate chain (PEM in memory)
 * @param[in] cert_chain Certificate chain PEM
 * @param[in] chain_len  Certificate chain length
 * @param[out] result    Verification result
 * @return 0 on success, negative on failure
 */
int cupolas_tls_verify_cert_chain(const char *cert_chain, size_t chain_len,
                                  cupolas_cert_mode_t *result);

/**
 * @brief Actively connect and check the host's certificate validity
 * @param[in] hostname Hostname
 * @param[in] port     Port
 * @param[out] result  Verification result
 * @return 0 on success, negative on failure
 */
int cupolas_tls_check_connection(const char *hostname, uint16_t port, cupolas_cert_mode_t *result);

/**
 * @brief Get the list of supported cipher suites
 * @param[out] suites Suite array (caller must free)
 * @param[out] count  Number of suites
 * @return 0 on success, negative on failure
 */
int cupolas_tls_get_cipher_suites(char ***suites, size_t *count);

/**
 * @brief Check whether a cipher suite is secure
 * @param[in] suite Suite name
 * @return 1 if secure, 0 if not
 */
int cupolas_tls_is_cipher_secure(const char *suite);

/**
 * @brief Add a network filter rule
 * @param[in] rule Rule
 * @return 0 on success, negative on failure
 */
int cupolas_net_add_rule(const cupolas_net_filter_rule_t *rule);

/**
 * @brief Remove a network filter rule
 * @param[in] rule_id Rule ID
 * @return 0 on success, negative on failure
 */
int cupolas_net_remove_rule(const char *rule_id);

/**
 * @brief Update a network filter rule
 * @param[in] rule_id Rule ID
 * @param[in] rule    New rule
 * @return 0 on success, negative on failure
 */
int cupolas_net_update_rule(const char *rule_id, const cupolas_net_filter_rule_t *rule);

/**
 * @brief Get a single network filter rule
 * @param[in] rule_id Rule ID
 * @param[out] rule   Rule output
 * @return 0 on success, negative on failure
 */
int cupolas_net_get_rule(const char *rule_id, cupolas_net_filter_rule_t *rule);

/**
 * @brief List all network filter rules
 * @param[out] rules Rule array (caller frees)
 * @param[out] count Number of rules
 * @return 0 on success, negative on failure
 */
int cupolas_net_list_rules(cupolas_net_filter_rule_t **rules, size_t *count);

/**
 * @brief Network access decision (host+port+protocol+direction)
 * @return 0 to allow, negative to deny
 */
int cupolas_net_check_access(const char *host, uint16_t port, cupolas_proto_t protocol,
                             const char *direction);

/**
 * @brief URL access decision (scheme/host/port/path, all dimensions)
 * @return 0 to allow, negative to deny
 */
int cupolas_net_check_url(const char *url, const char *method);

/**
 * @brief Configure the HTTP security policy
 * @return 0 on success, negative on failure
 */
int cupolas_http_configure(const cupolas_http_security_config_t *manager);

/**
 * @brief Validate an HTTP request (method/url/headers/body_size)
 * @return 0 to allow, negative to deny
 */
int cupolas_http_validate_request(const char *method, const char *url, const char **headers,
                                  size_t header_count, size_t body_size);

/**
 * @brief Append security headers to a response (HSTS/CSP etc.)
 * @return 0 on success, negative on failure
 */
int cupolas_http_add_security_headers(const char **headers, size_t header_count,
                                      size_t max_headers);

/**
 * @brief Check whether a URL is safe
 * @return 1 if safe, 0 if not
 */
int cupolas_http_is_url_safe(const char *url);

/**
 * @brief Configure the DNS security policy
 * @return 0 on success, negative on failure
 */
int cupolas_dns_configure(const cupolas_dns_security_config_t *manager);

/**
 * @brief Secure DNS resolution (constrained by the domain whitelist)
 * @return 0 on success, negative on failure
 */
int cupolas_dns_resolve(const char *hostname, char *ip_out, size_t ip_len);

/**
 * @brief Check whether a domain is allowed to be resolved
 * @return 1 if allowed, 0 if denied
 */
int cupolas_dns_is_domain_allowed(const char *domain);

/**
 * @brief Verify the DNSSEC signature of a domain
 * @return 0 if verified, negative on failure/unsigned
 */
int cupolas_dns_verify_dnssec(const char *domain);

/**
 * @brief Get the list of active connections
 * @return 0 on success, negative on failure
 */
int cupolas_net_get_connections(cupolas_connection_info_t **connections, size_t *count);

/**
 * @brief Close a specific connection
 * @return 0 on success, negative on failure
 */
int cupolas_net_close_connection(const char *local_ip, uint16_t local_port, const char *remote_ip,
                                 uint16_t remote_port);

/**
 * @brief Get network security statistics
 * @return 0 on success, negative on failure
 */
int cupolas_net_get_stats(cupolas_net_stats_t *stats);

/**
 * @brief Reset network security statistics
 */
void cupolas_net_reset_stats(void);

/**
 * @brief Enable/disable intrusion detection (IDS)
 * @return 0 on success, negative on failure
 */
int cupolas_net_ids_enable(bool enabled);

/**
 * @brief Run anomaly detection on a connection
 * @return 0 if normal, negative if anomalous
 */
int cupolas_net_detect_anomaly(const cupolas_connection_info_t *connection);

/**
 * @brief Register an IDS alert callback
 * @return 0 on success, negative on failure
 */
int cupolas_net_ids_set_callback(void (*callback)(const char *alert_type, const char *details,
                                                  const cupolas_connection_info_t *conn));

/**
 * @brief Parse a URL (scheme/host/port/path)
 * @return 0 on success, negative on failure
 */
int cupolas_net_parse_url(const char *url, char *scheme, char *host, uint16_t *port, char *path);

/**
 * @brief Check whether an IP is inside a CIDR range
 * @return 1 if inside, 0 if not
 */
int cupolas_net_ip_in_cidr(const char *ip, const char *cidr);

/**
 * @brief Validate an IP address format
 * @return 0 if valid, negative if invalid
 */
int cupolas_net_validate_ip(const char *ip);

/**
 * @brief Validate a port number range
 * @return 0 if valid, negative if invalid
 */
int cupolas_net_validate_port(uint16_t port);

/**
 * @brief Certificate validation result string
 * @return Static string (do not free)
 */
const char *cupolas_cert_result_string(cupolas_cert_mode_t result);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_NETWORK_SECURITY_H */
