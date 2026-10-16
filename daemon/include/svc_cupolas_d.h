/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/* @generated DO NOT EDIT — daemon_gen.py v1.15.0 (L3 SSoT)；改 .manifest 后重跑 --gen。 */

#ifndef SVC_CUPOLAS_D_H
#define SVC_CUPOLAS_D_H

#include "platform.h"
#include "daemon_main.h"
#include "airy_defaults.h"

#include <cjson/cJSON.h>

/* 端点常量（wire 契约，与 .manifest rpc 段一致） */
#define CUPOLAS_D_SOCKET_UNIX airy_runtime_dir_socket("cupolas.sock")
#define CUPOLAS_D_SOCKET_WIN "\\\\.\\pipe\\airy_cupolas"
/* TCP 口为 SSoT 引用，真值唯一定义于 airy_defaults.h */
#define CUPOLAS_D_TCP_PORT AIRY_PORT_CUPOLAS_D
#define CUPOLAS_D_MAX_BUFFER 65536

/* 端点解析钩子（.manifest endpoint=apply 派生的机制壳；机制体单点
 * 在 daemon_ep_base/daemon_ep_apply，daemon_cfg_file.c）。cmdline
 * use_tcp 融合与监听地址日志由 daemon_boot 机制层承载。 */
static inline void svc_endpoint(daemon_endpoint_t *ep, int cmdline_tcp)
{
    daemon_ep_apply(ep, cmdline_tcp);
}

/* 生命周期钩子（实现: src/svc.c）。prepare/destroy 恒有策略；
 * activate/attach/teardown 无策略需求者（noop_hooks，0.1.19
 * §80）由机制层 svc_<hook>_noop 缺省（daemon_main.h），
 * 此处不发声明，svc.c 不维护空桩副本。activate 收到事件驱动与
 * SD bootstrap 句柄；attach 为 SVC_METHODS 落库后的动态注册
 * 出口（dispatcher 为 method_dispatcher_t）。 */
int svc_prepare(const char *config_path);
void svc_destroy(void);

/* RPC 方法清单（唯一声明源，源自 .manifest rpc.methods）。
 * RPC_METHODS 只含策略方法；METHODS 追加协议保留 shutdown
 * （main.c DAEMON_DECLARE_SHUTDOWN_METHOD 生成为 static inline，
 * 不可对外发原型）。main.c 以 DAEMON_METHOD_ENTRY 展开 METHODS
 * 为 daemon_method_entry_t[]，本头以 DAEMON_M_DECL 展开
 * RPC_METHODS 为 m_<method> 原型（逐户声明块副本消解）。 */
#define SVC_CUPOLAS_D_RPC_METHODS(X) \
    X("check_permission", m_check_permission) \
    X("sanitize", m_sanitize) \
    X("execute_command", m_execute_command) \
    X("add_rule", m_add_rule) \
    X("audit_flush", m_audit_flush) \
    X("health_check", m_health_check) \
    X("get_stats", m_get_stats) \
    X("vault_store", m_vault_store) \
    X("vault_retrieve", m_vault_retrieve) \
    X("vault_delete", m_vault_delete) \
    X("vault_list", m_vault_list) \
    X("vault_rotate", m_vault_rotate) \
    X("net_add_rule", m_net_add_rule) \
    X("net_check_access", m_net_check_access) \
    X("net_get_stats", m_net_get_stats) \
    X("entitlements_load", m_entitlements_load) \
    X("entitlements_check", m_entitlements_check) \
    X("policy_load", m_policy_load) \
    X("policy_activate", m_policy_activate) \
    X("policy_rollback", m_policy_rollback) \
    X("policy_status", m_policy_status)

#define SVC_CUPOLAS_D_METHODS(X) \
    SVC_CUPOLAS_D_RPC_METHODS(X) \
    X("shutdown", on_shutdown_method_cupolas_d)

/* RPC handler 族原型（实现: src/svc.c，壳经 DAEMON_RPC_SHELL 族）。 */
SVC_CUPOLAS_D_RPC_METHODS(DAEMON_M_DECL)

#endif /* SVC_CUPOLAS_D_H */
