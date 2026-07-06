**语言:** [English](README.md) | 简体中文

# Airymax Cupolas — 安全穹顶

`agentrt/cupolas/`

**版本：** 0.1.1
**许可证：** AGPL-3.0-or-later OR Apache-2.0（双许可证）
**分支：** `feature/official-hubs-01`

---

## 1. 模块定位

Cupolas（穹顶）是 Airymax 智能体运行时的**应用语义安全层**（B 类），
是所有运行时安全裁决与执行的统一伞罩。Cupolas 实现四层内生安全模型——
每个 Agent 动作必须依次穿透四层才能触达内核：

1. **沙箱隔离** —— 每个不可信任务都在受限 Workbench 中执行
   （进程/容器隔离 + 资源限制）。
2. **RBAC 权限裁决** —— 每个动作都经过 RBAC + ABAC 权限引擎裁决，
   规则按优先级排序，并带权限缓存。
3. **输入净化** —— 每个输入在触达执行器之前，先清洗 XSS、SQL 注入、
   命令注入、路径遍历。
4. **审计追踪** —— 每个安全事件都写入异步、HMAC 签名链式、轮转的
   审计日志，支持取证溯源。

Cupolas 遵循纵深防御与零信任原则：默认拒绝、按调用身份与上下文授权、
全量可审计、最小权限，以及可动态扩展的安全守卫框架。

---

## 2. 目录结构

```
cupolas/
├── CMakeLists.txt                        # CMake 构建配置
├── README.md                             # 英文版
├── README_zh.md                          # 本文件（中文）
├── LICENSE                               # 双许可证文本（AGPL-3.0 + Apache-2.0）
├── NOTICE                                # 版权声明
├── include/                              # 公共头文件
│   ├── cupolas.h                         # Cupolas 统一入口
│   ├── zero_trust_integration.h          # 零信任集成接口
│   ├── dynamic_policy_engine.h           # 动态策略引擎
│   └── safety_guard.h                    # 安全守卫接口
└── src/
    ├── cupolas.c                         # Cupolas 核心实现
    ├── cupolas_config.c/.h               # 配置管理
    ├── cupolas_metrics.c/.h              # 指标采集
    ├── cupolas_monitoring.c/.h           # 监控系统
    ├── circuit_breaker.c/.h              # 熔断器
    ├── yaml_minimal.c/.h                 # YAML 1.1 解析器（后备）
    ├── slab.c/.h                         # Slab 分配器
    ├── mempool.c/.h                      # 内存池
    ├── platform/
    │   └── platform.c/.h                 # 平台安全适配
    ├── sanitizer/                        # （第 3 层）输入清洗器
    │   ├── sanitizer.h
    │   ├── sanitizer_core.c
    │   ├── sanitizer_rules.c/.h          # 规则引擎
    │   └── sanitizer_cache.c/.h          # 清洗缓存
    ├── permission/                       # （第 2 层）RBAC 权限引擎
    │   ├── permission.h
    │   ├── permission_engine.c/.h
    │   ├── permission_rule.c/.h
    │   └── permission_cache.c/.h
    ├── audit/                            # （第 4 层）审计系统
    │   ├── audit.h
    │   ├── audit_logger.c                # 审计日志器
    │   ├── audit_queue.c/.h              # 线程安全队列
    │   ├── audit_rotator.c/.h            # 日志轮转
    │   └── audit_overflow.c/.h           # 溢出处理
    ├── security/                         # 安全防护引擎
    │   ├── cupolas_error.c/.h            # 统一错误处理
    │   ├── cupolas_signature.c/.h        # 数字签名（OpenSSL）
    │   ├── cupolas_vault.c/.h            # 密钥保险库（OpenSSL）
    │   ├── cupolas_entitlements.c/.h     # 权利管理（OpenSSL）
    │   ├── cupolas_runtime_protection.c/.h  # 运行时保护（OpenSSL）
    │   ├── cupolas_network_security.c/.h    # 网络安全（OpenSSL）
    │   └── network/                      # 网络安全子模块
    │       ├── http_security.c/.h        # HTTP 安全
    │       ├── dns_security.c/.h         # DNS 安全
    │       ├── network_filter.c/.h       # 网络过滤
    │       ├── network_utils.c/.h        # 网络工具
    │       └── tls_security.c/.h         # TLS 安全（OpenSSL）
    ├── guards/                           # 可扩展守卫框架
    │   ├── guard_core.c/.h
    │   ├── guard_integration.c/.h
    │   └── safety_guard.c/.h
    ├── workbench/                        # （第 1 层）沙箱工作台
    │   ├── workbench.c/.h
    │   ├── workbench_process.h           # 进程管理接口
    │   ├── workbench_process_core.c      # 进程管理实现
    │   ├── workbench_container.c/.h      # 容器隔离
    │   └── workbench_limits.c/.h         # 资源限制
    └── utils/
        └── cupolas_utils.c/.h            # 内存、错误、日志、位操作工具
```

### 核心子系统

| 子系统 | 路径 | 职责 |
|--------|------|------|
| **输入清洗器** | `src/sanitizer/` | XSS / SQL 注入 / 命令注入 / 路径遍历防护 |
| **权限管理** | `src/permission/` | RBAC + ABAC 权限引擎，规则优先级排序，缓存 |
| **审计系统** | `src/audit/` | 异步写入、HMAC 签名链、日志轮转 |
| **安全防护引擎** | `src/security/` | 数字签名、密钥保险库、权利管理、运行时保护、网络安全 |
| **安全工作台** | `src/workbench/` | 隔离执行、资源控制、进程管理 |
| **安全守卫** | `src/guards/` | 可扩展检测框架（规则/模型/行为/启发式/外部/复合/自定义） |
| **安全工具库** | `src/utils/` | 内存管理、错误处理、日志、编译器提示、位操作、时间工具 |

### OpenSSL 条件编译模块

当定义 `AGENTRT_HAS_OPENSSL` 时，以下 iOS 级安全模块会被启用：

| 模块 | 源文件 | 职责 |
|------|--------|------|
| **数字签名** | `cupolas_signature.c` | RSA/ECDSA/Ed25519 签名验证、证书链校验、完整性校验 |
| **密钥保险库** | `cupolas_vault.c` | AES-256-GCM 凭证存储，ACL 访问控制，凭证轮换 |
| **权利管理** | `cupolas_entitlements.c` | 声明式权限（文件系统/网络/IPC/Vault/资源限制/Syscall/Capability） |
| **运行时保护** | `cupolas_runtime_protection.c` | seccomp、CFI、内存保护、完整性校验 |
| **网络安全** | `cupolas_network_security.c` | TLS 连接管理、防火墙规则、证书验证 |
| **TLS 安全** | `network/tls_security.c` | TLS/SSL 连接管理与证书验证 |

---

## 3. 上游 / 下游依赖关系

### 上游（Cupolas 依赖）

| 依赖 | 必需 | 用途 |
|------|------|------|
| **commons** | 是 | 同步原语、错误框架、类型定义、内存管理宏——直接消费基础层 |
| **atoms** | 是 | 提供 Cupolas 强制执行的 Syscall 表面（沙箱、seccomp、capability），以及审计队列所需的 CoreKern IPC 原语 |
| OpenSSL | 否 | 数字签名、密钥保险库、TLS——由 `AGENTRT_HAS_OPENSSL` 门控 |
| libyaml | 否 | 完整 YAML 支持（内置 `yaml_minimal.c` 作为后备） |
| cJSON | 否 | JSON 配置解析 |

> **BAN-12**：所有 `find_package` 在伞仓根 `CMakeLists.txt` 中集中完成，
> 子模块仅引用缓存变量。

### 下游（消费 Cupolas）

| 消费者 | 用途 |
|--------|------|
| **daemons** | 每个守护进程都调用 Cupolas 进行权限裁决、输入净化、写入审计事件；Workbench 承载不可信工具执行 |
| **gateway** | 网关在协议边界调用 Cupolas 进行请求鉴权和输入净化 |
| 外部 SDK / Agent 应用 | 使用 `cupolas_check_permission` 与 `cupolas_sanitize_input` 接入安全契约 |

---

## 4. 公共 API（`cupolas.h`）

| 函数 | 说明 |
|------|------|
| `cupolas_init(config_path, error)` | 初始化 Cupolas 模块 |
| `cupolas_cleanup()` | 清理 Cupolas 模块 |
| `cupolas_version()` | 获取版本字符串 |
| `cupolas_check_permission(agent_id, action, resource, context)` | 权限检查（1=允许，0=拒绝） |
| `cupolas_add_permission_rule(agent_id, action, resource, allow, priority)` | 添加权限规则 |
| `cupolas_clear_permission_cache()` | 清除权限缓存 |
| `cupolas_sanitize_input(input, output, output_size)` | 输入清洗 |
| `cupolas_execute_command(command, argv, exit_code, ...)` | 在隔离工作台中执行命令 |
| `cupolas_flush_audit_log()` | 刷新审计日志 |

### 架构总览

```
+-----------------------------------------------------------------------+
|                        安全保障体系（Cupolas）                         |
+-----------------------------------------------------------------------+
|  +-----------+  +-----------+  +-----------+                          |
|  | Workbench |  | Sanitizer |  | Permission|   （四层内生安全）         |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |   Audit   |  |   Utils   |  |  Security |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |  Guards   |  |CircuitBrkr|  |YAMLParser |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +----------------------------------------------------------------+   |
|  |              OpenSSL 条件模块（AGENTRT_HAS_OPENSSL）             |   |
|  | Signature | Vault | Entitlements | RuntimeProt | NetSec | TLS  |   |
|  +----------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
|                      系统调用层（atoms/syscall）                       |
+-----------------------------------------------------------------------+
```

---

## 5. 构建说明

```bash
# 标准构建（在伞仓根目录或本仓独立构建）
cmake -B build -DBUILD_TESTS=ON -DBUILD_WITH_SANITIZERS=OFF
cmake --build build

# 运行测试套件（unit / integration / stress / fuzz / benchmark）
ctest --test-dir build
```

### CMake 选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `BUILD_TESTS` | `ON` | 构建测试套件（单元/集成/压力/模糊/基准） |
| `BUILD_WITH_SANITIZERS` | `OFF` | 启用 ASAN/MSAN/TSAN |
| `BUILD_WITH_LOGGING` | `ON` | 启用详细日志 |
| `AGENTRT_HAS_OPENSSL` | 自动 | 由伞仓 CMake 自动检测，门控 OpenSSL 条件模块 |
| `AGENTRT_HAS_YAML` | 自动 | 由伞仓 CMake 自动检测 |
| `AGENTRT_HAS_CJSON` | 自动 | 由伞仓 CMake 自动检测 |

### 编译安全选项（Linux）

- `-fstack-protector-strong` —— 栈保护
- `-D_FORTIFY_SOURCE=2` —— 缓冲区溢出保护
- `-fvisibility=hidden` —— 符号隐藏
- `-Wl,-z,relro,-z,now` —— 只读重定位
- `-Wl,-z,noexecstack` —— 禁止栈执行

### 构建产物

- `agentrt_cupolas` —— 聚合所有安全子系统的静态库
- 公共头文件安装到 `include/agentrt/cupolas`

### 安装

```bash
cmake --install build --prefix /opt/airymax
```

---

## 6. 许可证

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

本模块采用双许可证，您可以选择以下任一许可证遵守：

- **GNU Affero General Public License v3.0 or later**
  ([AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.txt))，或
- **Apache License, Version 2.0**
  ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.txt))

SPDX-License-Identifier: `AGPL-3.0-or-later OR Apache-2.0`

完整许可证文本见 [LICENSE](LICENSE) 文件，版权声明见 [NOTICE](NOTICE)。
默认适用 AGPL-3.0-or-later 条款；Apache-2.0 备选用于 AGPL 无法覆盖的
下游集成场景（如闭源或专有分发）。
