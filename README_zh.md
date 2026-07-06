# cupolas — 安全穹顶

> 四层固有安全：每个智能体动作在抵达内核前都必须穿过穹顶。
> [agentrt](../) 管理仓下的叶子仓。

**语言:** [English](README.md) | 简体中文

[![Version](https://img.shields.io/badge/version-0.1.1-5a6b7e)](https://atomgit.com/openairymax/cupolas)
[![License](https://img.shields.io/badge/license-AGPL--3.0+Apache--2.0-4a90d9)](LICENSE)
[![C11](https://img.shields.io/badge/C-11-00599C?logo=c&logoColor=white)](https://en.cppreference.com/w/c/11)

- **仓库地址：** `git@atomgit.com:openairymax/cupolas.git`
- **分支：** `feature/official-hubs-01`
- **版本：** 0.1.1（Airymax 奠基版本）

---

## 概述

**cupolas**（字面意为"穹顶"）是 Airymax 智能体运行时的**应用语义安全层**。所有运行时安全决策都在穹顶下做出并执行。cupolas 实现四层内生安全模型——智能体动作在抵达内核前必须穿过每一层：

1. **沙箱隔离** —— 每个不可信任务在受限 workbench 中运行（进程/容器隔离 + 资源限制）。
2. **RBAC 权限裁定** —— 每个动作都经过 RBAC + ABAC 权限引擎检查，支持规则优先级排序和权限缓存。
3. **输入净化** —— 每个输入在触达执行器前都被清洗以防御 XSS、SQL 注入、命令注入和路径穿越。
4. **审计追踪** —— 每个安全事件都写入异步、HMAC 签名、轮转的审计日志，用于取证可追溯。

cupolas 遵循纵深防御和零信任原则：默认拒绝、每次调用基于身份与上下文授权、完全可审计、最小权限、动态可扩展的 guard 框架。它构建单一静态库 `agentrt_cupolas`，聚合所有安全子系统，OpenSSL 条件的 iOS 级模块（签名、密钥库、entitlements、运行时保护、网络/TLS 安全）由 `AGENTRT_HAS_OPENSSL` 门控。

在 Airymax 0.1.1 发行版中，工作区被拆分为 **38 个仓库**（1 umbrella + 5 management + 29 leaf + 3 top-level）；`cupolas` 是 [agentrt](../) 管理仓聚合的 7 个叶子仓之一，在循环分层架构中位于内核层（`atoms`）与服务/组合层（`gateway`、`daemons`）之间。

## 模块分类

**B 类 —— 行为 / 安全。**

与 A 类基础模块（atoms、commons）不同，cupolas 是行为模块：它不提供其他模块构建*其上*的原语，而是强制执行其他模块必须*穿过*的策略。它依赖 `atoms`（提供 Syscall 沙箱/seccomp/capability 接口和用于审计队列的 CoreKern IPC 原语）和 `commons`（提供同步、错误框架、类型、内存宏）。其消费者——`gateway` 和 `daemons`——在每个安全边界（请求认证、输入净化、权限检查、审计发射）调用 cupolas。

## 目录结构

```
cupolas/
├── CMakeLists.txt                        # CMake 构建配置（单一静态库 agentrt_cupolas）
├── README.md                             # 英文版
├── README_zh.md                          # 本文件（中文）
├── LICENSE                               # 双许可证文本（AGPL-3.0 + Apache-2.0）
├── NOTICE                                # 版权声明
├── include/                              # 公共头文件
│   ├── cupolas.h                         # Cupolas 统一入口
│   ├── zero_trust_integration.h          # 零信任集成接口
│   ├── dynamic_policy_engine.h           # 动态策略引擎
│   └── safety_guard.h                    # 安全 guard 接口
└── src/
    ├── cupolas.c                         # Cupolas 核心实现
    ├── cupolas_config.c/.h               # 配置管理
    ├── cupolas_metrics.c/.h              # 指标采集
    ├── cupolas_monitoring.c/.h           # 运行时监控
    ├── circuit_breaker.c/.h              # 熔断器
    ├── yaml_minimal.c/.h                 # YAML 1.1 解析器（回退）
    ├── slab.c/.h                         # Slab 分配器
    ├── mempool.c/.h                      # 内存池
    ├── platform/
    │   └── platform.c/.h                 # 平台安全适配
    ├── sanitizer/                        #（第 3 层）输入净化器
    │   ├── sanitizer.h
    │   ├── sanitizer_core.c
    │   ├── sanitizer_rules.c/.h          # 规则引擎
    │   └── sanitizer_cache.c/.h          # 净化缓存
    ├── permission/                       #（第 2 层）RBAC 权限引擎
    │   ├── permission.h
    │   ├── permission_engine.c/.h
    │   ├── permission_rule.c/.h
    │   └── permission_cache.c/.h
    ├── audit/                            #（第 4 层）审计系统
    │   ├── audit.h
    │   ├── audit_logger.c                # 审计日志器
    │   ├── audit_queue.c/.h              # 线程安全队列
    │   ├── audit_rotator.c/.h            # 日志轮转
    │   └── audit_overflow.c/.h           # 溢出处理
    ├── security/                         # 安全防御引擎
    │   ├── cupolas_error.c/.h            # 统一错误处理
    │   ├── cupolas_signature.c/.h        # 数字签名（OpenSSL）
    │   ├── cupolas_vault.c/.h            # 密钥库（OpenSSL）
    │   ├── cupolas_entitlements.c/.h     # Entitlements（OpenSSL）
    │   ├── cupolas_runtime_protection.c/.h  # 运行时保护（OpenSSL）
    │   ├── cupolas_network_security.c/.h    # 网络安全（OpenSSL）
    │   └── network/                      # 网络安全子模块
    │       ├── http_security.c/.h        # HTTP 安全
    │       ├── dns_security.c/.h         # DNS 安全
    │       ├── network_filter.c/.h       # 网络过滤
    │       ├── network_utils.c/.h        # 网络工具
    │       └── tls_security.c/.h         # TLS 安全（OpenSSL）
    ├── guards/                           # 可扩展 guard 框架
    │   ├── guard_core.c/.h
    │   ├── guard_integration.c/.h
    │   └── safety_guard.c/.h
    ├── workbench/                        #（第 1 层）沙箱 workbench
    │   ├── workbench.c/.h
    │   ├── workbench_process.h           # 进程管理接口
    │   ├── workbench_process_core.c      # 进程管理实现
    │   ├── workbench_container.c/.h      # 容器隔离
    │   └── workbench_limits.c/.h         # 资源限制
    └── utils/
        └── cupolas_utils.c/.h            # 内存、错误、日志、位操作助手
```

## 核心组件

| 子系统 | 路径 | 职责 |
|--------|------|------|
| **Workbench**（第 1 层） | `src/workbench/` | 隔离执行、资源控制、进程管理、容器隔离 |
| **Permission**（第 2 层） | `src/permission/` | RBAC + ABAC 引擎、规则优先级排序、权限缓存 |
| **Input Sanitizer**（第 3 层） | `src/sanitizer/` | XSS / SQL 注入 / 命令注入 / 路径穿越防御；规则引擎 + 缓存 |
| **Audit**（第 4 层） | `src/audit/` | 异步写入、HMAC 签名链、日志轮转、溢出处理、线程安全队列 |
| **Security Engine** | `src/security/` | 数字签名、密钥库、entitlements、运行时保护、网络安全 |
| **Guards** | `src/guards/` | 可扩展检测框架（规则/模型/行为/启发式/外部/复合/自定义） |
| **Core** | `src/cupolas.c` | 模块生命周期、配置、指标、监控、熔断器 |
| **Utils** | `src/utils/` | 内存管理（slab/mempool）、错误处理、日志、编译器提示、位操作、时间 |

### OpenSSL 条件模块

当定义 `AGENTRT_HAS_OPENSSL` 时，启用以下 iOS 级安全模块：

| 模块 | 源文件 | 职责 |
|------|--------|------|
| **Digital Signature** | `cupolas_signature.c` | RSA/ECDSA/Ed25519 验签、证书链、完整性 |
| **Key Vault** | `cupolas_vault.c` | AES-256-GCM 凭据存储、ACL、轮换 |
| **Entitlements** | `cupolas_entitlements.c` | 声明式权限（FS / 网络 / IPC / 密钥库 / 配额 / syscall / capability） |
| **Runtime Protection** | `cupolas_runtime_protection.c` | seccomp、CFI、内存保护、完整性检查 |
| **Network Security** | `cupolas_network_security.c` | TLS 连接管理、防火墙规则、证书验证 |
| **TLS Security** | `network/tls_security.c` | TLS/SSL 连接管理与证书验证 |

## 架构

```
+-----------------------------------------------------------------------+
|                   安全保障系统（cupolas）                              |
+-----------------------------------------------------------------------+
|  +-----------+  +-----------+  +-----------+                          |
|  | Workbench |  | Sanitizer |  | Permission|   （4 层内生安全）        |
|  | (第 1 层)  |  | (第 3 层) |  | (第 2 层) |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |   Audit   |  |   Utils   |  |  Security |   （第 4 层 + 引擎）      |
|  | (第 4 层)  |  |           |  |  Engine   |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |  Guards   |  |CircuitBrkr|  |YAMLParser |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +----------------------------------------------------------------+   |
|  |        OpenSSL 条件（AGENTRT_HAS_OPENSSL）                      |   |
|  | Signature | Vault | Entitlements | RuntimeProt | NetSec | TLS  |   |
|  +----------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
|                      系统调用层（atoms/syscall）                       |
+-----------------------------------------------------------------------+

  请求流：gateway/daemon → cupolas → [沙箱 → 权限 → 净化] → atoms/内核
                                                          ↓
                                                      审计日志
```

**设计原则：** 纵深防御、零信任（默认拒绝、每次调用基于身份 + 上下文）、完全可审计、最小权限、动态可扩展 guard 框架、内生安全（每层都必须穿过）。

## 上游依赖

> `commons` 是所有 agentrt 模块的基础库；cupolas 直接消费它。cupolas 还依赖 `atoms` 作为强制执行基底。

| 依赖 | 是否必需 | 用途 |
|------|----------|------|
| **commons** | 是 | 同步原语、错误框架、类型定义（`agentrt_types.h`）、内存管理宏（`AGENTRT_MALLOC`/`FREE`）、security/resource 工具——直接消费基础层 |
| **atoms** | 是 | 提供 cupolas 强制执行的 Syscall 接口（沙箱、seccomp、capability、4 级保护环），以及用于审计队列和 workbench IPC 的 CoreKern IPC 原语（`are_ipc.h`） |
| OpenSSL | 否 | 数字签名、密钥库、entitlements、运行时保护、TLS——由 `AGENTRT_HAS_OPENSSL` 门控 |
| libyaml | 否 | 完整 YAML 支持；内置 `yaml_minimal.c` 为回退 |
| cJSON | 否 | JSON 配置解析 |

> **BAN-12**：所有 `find_package` 调用集中在伞仓根 `CMakeLists.txt`；子模块仅消费缓存变量（`AGENTRT_HAS_OPENSSL`、`AGENTRT_HAS_YAML`、`AGENTRT_HAS_CJSON`）。

## 下游消费者

| 消费者 | 用途 |
|--------|------|
| **daemons** | 每个守护进程调用 cupolas 进行权限检查（`cupolas_check_permission`）、输入净化（`cupolas_sanitize_input`），并发射审计事件；workbench 托管不可信工具执行（如 `tool_d` 在 `cupolas_execute_command` 内运行工具命令） |
| **gateway** | 网关在协议边界调用 cupolas 进行请求认证和输入净化，在将 HTTP/WS/stdio 翻译为 JSON-RPC 之前 |
| 外部 SDK / 智能体应用 | 使用 `cupolas_check_permission` 和 `cupolas_sanitize_input` 参与安全契约；safety_guard / zero_trust_integration 接口让外部智能体接入穹顶 |

## 构建

```bash
# 标准构建（源外构建，BAN-33 强制要求）
cmake -S . -B /tmp/cupolas-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build /tmp/cupolas-build --parallel $(nproc)

# 运行测试套件（单元/集成/压力/fuzz/基准）
ctest --test-dir /tmp/cupolas-build --output-on-failure

# 安装
cmake --install /tmp/cupolas-build --prefix /opt/airymax
```

**CMake 选项：**

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `BUILD_TESTS` | `ON` | 构建测试套件（单元/集成/压力/fuzz/基准） |
| `BUILD_WITH_SANITIZERS` | `OFF` | 启用 ASAN / MSAN / TSAN |
| `BUILD_WITH_LOGGING` | `ON` | 启用详细日志 |
| `AGENTRT_HAS_OPENSSL` | 自动 | 由伞仓 CMake 自动探测；门控 OpenSSL 条件模块 |
| `AGENTRT_HAS_YAML` | 自动 | 由伞仓 CMake 自动探测 |
| `AGENTRT_HAS_CJSON` | 自动 | 由伞仓 CMake 自动探测 |

**强化构建标志（Linux）：** `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`、`-fvisibility=hidden`、`-Wl,-z,relro,-z,now`、`-Wl,-z,noexecstack`。

**构建产物：**

- `agentrt_cupolas` —— 聚合所有安全子系统的静态库
- 公共头文件安装到 `include/agentrt/cupolas`

## API

公共 API 接口通过 `include/cupolas.h`（统一入口）及配套头 `zero_trust_integration.h`、`dynamic_policy_engine.h`、`safety_guard.h` 导出。

| 函数 | 说明 |
|------|------|
| `cupolas_init(config_path, error)` | 初始化 cupolas 模块 |
| `cupolas_cleanup()` | 销毁 cupolas 模块 |
| `cupolas_version()` | 获取版本字符串 |
| `cupolas_check_permission(agent_id, action, resource, context)` | 权限检查（1 = 允许，0 = 拒绝） |
| `cupolas_add_permission_rule(agent_id, action, resource, allow, priority)` | 添加权限规则 |
| `cupolas_clear_permission_cache()` | 清除权限缓存 |
| `cupolas_sanitize_input(input, output, output_size)` | 净化输入（XSS / SQLi / 命令注入 / 路径穿越） |
| `cupolas_execute_command(command, argv, exit_code, ...)` | 在隔离 workbench 内执行命令 |
| `cupolas_flush_audit_log()` | 刷新审计日志 |

可扩展 guard 框架（`safety_guard.h`）支持规则/模型/行为/启发式/外部/复合/自定义 guard 类型。零信任集成接口让外部智能体注册上下文提供者，实现基于身份与上下文的授权。

## 许可证

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

本模块采用双许可证，您可以选择以下任一许可证遵守：

- **GNU Affero General Public License v3.0 or later**
  ([AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.txt))，或
- **Apache License, Version 2.0**
  ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.txt))

SPDX-License-Identifier: `AGPL-3.0-or-later OR Apache-2.0`

完整许可证文本见 [LICENSE](LICENSE) 文件；版权声明见 [NOTICE](NOTICE)。默认适用 AGPL-3.0-or-later 条款；Apache-2.0 备选用于 AGPL 无法覆盖的下游集成场景（如闭源或专有分发）。
