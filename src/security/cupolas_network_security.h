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
 * 公共 API（与 cupolas_network_security.c 实现一一对应）
 *
 * 历史遗留：旧代 API（cupolas_network_security_init、cupolas_tls_*、
 * cupolas_firewall_*、cupolas_cert_* 共 30 个）仅在头文件声明、实现缺失，
 * 任何调用方链接必失败。
 * 现按实现（cupolas_net_* 新代）对齐声明，消除「声明与实现断裂」。
 * ============================================================================ */

/**
 * @brief 初始化网络安全模块（默认 TLS 1.2-1.3、强制 HTTPS、DNSSEC）
 * @param[in] manager 配置（NULL 使用安全默认值）
 * @return 0 成功，负值失败
 */
int cupolas_net_security_init(const cupolas_tls_config_t *manager);

/**
 * @brief 关闭网络安全模块
 */
void cupolas_net_security_cleanup(void);

/**
 * @brief 读取当前安全配置
 * @param[out] manager 配置输出
 * @return 0 成功，负值失败
 */
int cupolas_net_security_get_config(cupolas_tls_config_t *manager);

/**
 * @brief 配置 TLS 策略（版本/密码套件/校验模式）
 * @param[in] manager 配置（NULL 使用安全默认值）
 * @return 0 成功，负值失败
 */
int cupolas_tls_configure(const cupolas_tls_config_t *manager);

/**
 * @brief 验证证书文件（路径）与主机名匹配
 * @param[in] cert_path 证书文件路径
 * @param[in] hostname  预期主机名
 * @param[out] result   验证结果（cupolas_cert_mode_t）
 * @return 0 成功，负值失败
 */
int cupolas_tls_verify_cert(const char *cert_path, const char *hostname,
                            cupolas_cert_mode_t *result);

/**
 * @brief 验证证书链（PEM 内存数据）
 * @param[in] cert_chain 证书链 PEM
 * @param[in] chain_len  证书链长度
 * @param[out] result    验证结果
 * @return 0 成功，负值失败
 */
int cupolas_tls_verify_cert_chain(const char *cert_chain, size_t chain_len,
                                  cupolas_cert_mode_t *result);

/**
 * @brief 主动连接检测主机证书有效性
 * @param[in] hostname 主机名
 * @param[in] port     端口
 * @param[out] result  验证结果
 * @return 0 成功，负值失败
 */
int cupolas_tls_check_connection(const char *hostname, uint16_t port, cupolas_cert_mode_t *result);

/**
 * @brief 获取支持的密码套件列表
 * @param[out] suites 套件数组（调用方须释放）
 * @param[out] count  套件数量
 * @return 0 成功，负值失败
 */
int cupolas_tls_get_cipher_suites(char ***suites, size_t *count);

/**
 * @brief 判断密码套件是否安全
 * @param[in] suite 套件名
 * @return 1 安全，0 不安全
 */
int cupolas_tls_is_cipher_secure(const char *suite);

/**
 * @brief 添加网络过滤规则
 * @param[in] rule 规则
 * @return 0 成功，负值失败
 */
int cupolas_net_add_rule(const cupolas_net_filter_rule_t *rule);

/**
 * @brief 删除网络过滤规则
 * @param[in] rule_id 规则 ID
 * @return 0 成功，负值失败
 */
int cupolas_net_remove_rule(const char *rule_id);

/**
 * @brief 更新网络过滤规则
 * @param[in] rule_id 规则 ID
 * @param[in] rule    新规则
 * @return 0 成功，负值失败
 */
int cupolas_net_update_rule(const char *rule_id, const cupolas_net_filter_rule_t *rule);

/**
 * @brief 查询单条网络过滤规则
 * @param[in] rule_id 规则 ID
 * @param[out] rule   规则输出
 * @return 0 成功，负值失败
 */
int cupolas_net_get_rule(const char *rule_id, cupolas_net_filter_rule_t *rule);

/**
 * @brief 列出全部网络过滤规则
 * @param[out] rules 规则数组（调用方释放）
 * @param[out] count 规则数量
 * @return 0 成功，负值失败
 */
int cupolas_net_list_rules(cupolas_net_filter_rule_t **rules, size_t *count);

/**
 * @brief 网络访问裁决（host+port+protocol+direction）
 * @return 0 允许，负值拒绝
 */
int cupolas_net_check_access(const char *host, uint16_t port, cupolas_proto_t protocol,
                             const char *direction);

/**
 * @brief URL 访问裁决（scheme/host/port/path 全维度）
 * @return 0 允许，负值拒绝
 */
int cupolas_net_check_url(const char *url, const char *method);

/**
 * @brief 配置 HTTP 安全策略
 * @return 0 成功，负值失败
 */
int cupolas_http_configure(const cupolas_http_security_config_t *manager);

/**
 * @brief 校验 HTTP 请求（method/url/headers/body_size）
 * @return 0 允许，负值拒绝
 */
int cupolas_http_validate_request(const char *method, const char *url, const char **headers,
                                  size_t header_count, size_t body_size);

/**
 * @brief 为响应追加安全头（HSTS/CSP 等）
 * @return 0 成功，负值失败
 */
int cupolas_http_add_security_headers(const char **headers, size_t header_count,
                                      size_t max_headers);

/**
 * @brief 判断 URL 是否安全
 * @return 1 安全，0 不安全
 */
int cupolas_http_is_url_safe(const char *url);

/**
 * @brief 配置 DNS 安全策略
 * @return 0 成功，负值失败
 */
int cupolas_dns_configure(const cupolas_dns_security_config_t *manager);

/**
 * @brief 安全 DNS 解析（受域名白名单约束）
 * @return 0 成功，负值失败
 */
int cupolas_dns_resolve(const char *hostname, char *ip_out, size_t ip_len);

/**
 * @brief 判断域名是否被允许解析
 * @return 1 允许，0 拒绝
 */
int cupolas_dns_is_domain_allowed(const char *domain);

/**
 * @brief 验证域名的 DNSSEC 签名
 * @return 0 验证通过，负值失败/未签名
 */
int cupolas_dns_verify_dnssec(const char *domain);

/**
 * @brief 获取活动连接列表
 * @return 0 成功，负值失败
 */
int cupolas_net_get_connections(cupolas_connection_info_t **connections, size_t *count);

/**
 * @brief 关闭指定连接
 * @return 0 成功，负值失败
 */
int cupolas_net_close_connection(const char *local_ip, uint16_t local_port, const char *remote_ip,
                                 uint16_t remote_port);

/**
 * @brief 获取网络安全统计
 * @return 0 成功，负值失败
 */
int cupolas_net_get_stats(cupolas_net_stats_t *stats);

/**
 * @brief 重置网络安全统计
 */
void cupolas_net_reset_stats(void);

/**
 * @brief 启用/关闭入侵检测（IDS）
 * @return 0 成功，负值失败
 */
int cupolas_net_ids_enable(bool enabled);

/**
 * @brief 对连接执行异常检测
 * @return 0 正常，负值异常
 */
int cupolas_net_detect_anomaly(const cupolas_connection_info_t *connection);

/**
 * @brief 注册 IDS 告警回调
 * @return 0 成功，负值失败
 */
int cupolas_net_ids_set_callback(void (*callback)(const char *alert_type, const char *details,
                                                  const cupolas_connection_info_t *conn));

/**
 * @brief 解析 URL（scheme/host/port/path）
 * @return 0 成功，负值失败
 */
int cupolas_net_parse_url(const char *url, char *scheme, char *host, uint16_t *port, char *path);

/**
 * @brief 判断 IP 是否在 CIDR 网段内
 * @return 1 在网段内，0 不在
 */
int cupolas_net_ip_in_cidr(const char *ip, const char *cidr);

/**
 * @brief 校验 IP 地址格式
 * @return 0 合法，负值非法
 */
int cupolas_net_validate_ip(const char *ip);

/**
 * @brief 校验端口号范围
 * @return 0 合法，负值非法
 */
int cupolas_net_validate_port(uint16_t port);

/**
 * @brief 证书验证结果字符串
 * @return 静态字符串（勿 free）
 */
const char *cupolas_cert_result_string(cupolas_cert_mode_t result);

#ifdef __cplusplus
}
#endif

#endif /* CUPOLAS_NETWORK_SECURITY_H */
