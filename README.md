# cupolas — Security Dome

> Four-layer inherent security: every agent action must pass through the dome before it reaches the kernel.
> Leaf repository under the [agentrt](../) management repo.

**Language:** English | [简体中文](README_zh.md)

[![Version](https://img.shields.io/badge/version-0.1.1-5a6b7e)](https://atomgit.com/openairymax/cupolas)
[![License](https://img.shields.io/badge/license-AGPL--3.0+Apache--2.0-4a90d9)](LICENSE)
[![C11](https://img.shields.io/badge/C-11-00599C?logo=c&logoColor=white)](https://en.cppreference.com/w/c/11)

- **Repository:** `git@atomgit.com:openairymax/cupolas.git`
- **Branch:** `feature/official-hubs-01`
- **Version:** 0.1.1 (Airymax foundational release)

---

## Overview

**cupolas** (literally "dome") is the **application-semantic security layer** of the Airymax agent runtime. It is the umbrella under which every runtime security decision is made and enforced. cupolas implements a four-layer endogenous-security model — every layer must be passed before an agent action reaches the kernel:

1. **Sandbox isolation** — every untrusted task runs in a confined workbench (process / container isolation with resource limits).
2. **RBAC permission adjudication** — every action is checked against an RBAC + ABAC permission engine with rule-priority ordering and a permission cache.
3. **Input sanitization** — every input is scrubbed for XSS, SQL injection, command injection, and path traversal before it touches an executor.
4. **Audit tracing** — every security event is written to an asynchronous, HMAC-signed, rotating audit log for forensic traceability.

cupolas follows defense-in-depth and zero-trust principles: default-deny, identity-and-context-based authorization per call, full auditability, least privilege, and a dynamically-extensible guard framework. It builds a single static library `airy_cupolas` aggregating all security subsystems, with OpenSSL-conditional iOS-grade modules (signature, vault, entitlements, runtime protection, network/TLS security) gated by `AIRY_HAS_OPENSSL`.

Within the Airymax 0.1.1 release, the workspace is partitioned into **38 repositories** (1 umbrella + 5 management + 29 leaf + 3 top-level); `cupolas` is one of the 7 leaf repositories aggregated by the [agentrt](../) management repo, sitting between the kernel layer (`atoms`) and the service/composition layer (`gateway`, `daemons`) in the cyclic layered architecture.

## Module Classification

**Class B — Behavioral / Safety.**

Unlike Class-A foundational modules (atoms, commons), cupolas is a behavioral module: it does not provide primitives that other modules build *on*, but rather enforces policies that other modules must *pass through*. It depends on `atoms` (for the Syscall sandbox/seccomp/capability surface and CoreKern IPC primitives for the audit queue) and `commons` (for sync, error framework, types, memory macros). Its consumers — `gateway` and `daemons` — invoke cupolas at every security boundary (request authentication, input sanitization, permission checks, audit emission).

## Directory Structure

```
cupolas/
├── CMakeLists.txt                        # CMake build configuration (single static lib airy_cupolas)
├── README.md                             # This file (English)
├── README_zh.md                          # Chinese version
├── LICENSE                               # Dual license texts (AGPL-3.0 + Apache-2.0)
├── NOTICE                                # Copyright notice
├── include/                              # Public headers
│   ├── cupolas.h                         # Cupolas unified entry
│   ├── zero_trust_integration.h          # Zero-trust integration interface
│   ├── dynamic_policy_engine.h           # Dynamic policy engine
│   └── safety_guard.h                    # Safety guard interface
└── src/
    ├── cupolas.c                         # Cupolas core implementation
    ├── cupolas_config.c/.h               # Configuration management
    ├── cupolas_metrics.c/.h              # Metric collection
    ├── cupolas_monitoring.c/.h           # Runtime monitoring
    ├── circuit_breaker.c/.h              # Circuit breaker
    ├── yaml_minimal.c/.h                 # YAML 1.1 parser (fallback)
    ├── slab.c/.h                         # Slab allocator
    ├── mempool.c/.h                      # Memory pool
    ├── platform/
    │   └── platform.c/.h                 # Platform security adaptation
    ├── sanitizer/                        # (Layer 3) Input sanitizer
    │   ├── sanitizer.h
    │   ├── sanitizer_core.c
    │   ├── sanitizer_rules.c/.h          # Rule engine
    │   └── sanitizer_cache.c/.h          # Sanitization cache
    ├── permission/                       # (Layer 2) RBAC permission engine
    │   ├── permission.h
    │   ├── permission_engine.c/.h
    │   ├── permission_rule.c/.h
    │   └── permission_cache.c/.h
    ├── audit/                            # (Layer 4) Audit system
    │   ├── audit.h
    │   ├── audit_logger.c                # Audit logger
    │   ├── audit_queue.c/.h              # Thread-safe queue
    │   ├── audit_rotator.c/.h            # Log rotation
    │   └── audit_overflow.c/.h           # Overflow handling
    ├── security/                         # Security defense engine
    │   ├── cupolas_error.c/.h            # Unified error handling
    │   ├── cupolas_signature.c/.h        # Digital signature (OpenSSL)
    │   ├── cupolas_vault.c/.h            # Key vault (OpenSSL)
    │   ├── cupolas_entitlements.c/.h     # Entitlements (OpenSSL)
    │   ├── cupolas_runtime_protection.c/.h  # Runtime protection (OpenSSL)
    │   ├── cupolas_network_security.c/.h    # Network security (OpenSSL)
    │   └── network/                      # Network security sub-modules
    │       ├── http_security.c/.h        # HTTP security
    │       ├── dns_security.c/.h         # DNS security
    │       ├── network_filter.c/.h       # Network filter
    │       ├── network_utils.c/.h        # Network utilities
    │       └── tls_security.c/.h         # TLS security (OpenSSL)
    ├── guards/                           # Extensible guard framework
    │   ├── guard_core.c/.h
    │   ├── guard_integration.c/.h
    │   └── safety_guard.c/.h
    ├── workbench/                        # (Layer 1) Sandbox workbench
    │   ├── workbench.c/.h
    │   ├── workbench_process.h           # Process management interface
    │   ├── workbench_process_core.c      # Process management impl
    │   ├── workbench_container.c/.h      # Container isolation
    │   └── workbench_limits.c/.h         # Resource limits
    └── utils/
        └── cupolas_utils.c/.h            # Memory, error, logging, bit ops helpers
```

## Core Components

| Subsystem | Path | Responsibility |
|-----------|------|----------------|
| **Workbench** (Layer 1) | `src/workbench/` | Isolated execution, resource control, process management, container isolation |
| **Permission** (Layer 2) | `src/permission/` | RBAC + ABAC engine, rule-priority ordering, permission cache |
| **Input Sanitizer** (Layer 3) | `src/sanitizer/` | XSS / SQL injection / command injection / path traversal defense; rule engine + cache |
| **Audit** (Layer 4) | `src/audit/` | Async writes, HMAC signature chain, log rotation, overflow handling, thread-safe queue |
| **Security Engine** | `src/security/` | Digital signature, key vault, entitlements, runtime protection, network security |
| **Guards** | `src/guards/` | Extensible detection framework (rule / model / behavior / heuristic / external / composite / custom) |
| **Core** | `src/cupolas.c` | Module lifecycle, config, metrics, monitoring, circuit breaker |
| **Utils** | `src/utils/` | Memory mgmt (slab/mempool), error handling, logging, compiler hints, bit ops, time |

### OpenSSL-conditional modules

When `AIRY_HAS_OPENSSL` is defined, the following iOS-grade security modules are enabled:

| Module | Source | Responsibility |
|--------|--------|----------------|
| **Digital Signature** | `cupolas_signature.c` | RSA/ECDSA/Ed25519 verification, certificate chain, integrity |
| **Key Vault** | `cupolas_vault.c` | AES-256-GCM credential storage, ACL, rotation |
| **Entitlements** | `cupolas_entitlements.c` | Declarative permissions (FS / network / IPC / vault / quota / syscall / capability) |
| **Runtime Protection** | `cupolas_runtime_protection.c` | seccomp, CFI, memory protection, integrity checks |
| **Network Security** | `cupolas_network_security.c` | TLS connection mgmt, firewall rules, cert verification |
| **TLS Security** | `network/tls_security.c` | TLS/SSL connection management and cert verification |

## Architecture

```
+-----------------------------------------------------------------------+
|                   Security Assurance System (cupolas)                 |
+-----------------------------------------------------------------------+
|  +-----------+  +-----------+  +-----------+                          |
|  | Workbench |  | Sanitizer |  | Permission|   (4 endogenous layers)  |
|  | (Layer 1) |  | (Layer 3) |  | (Layer 2) |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |   Audit   |  |   Utils   |  |  Security |   (Layer 4 + engine)     |
|  | (Layer 4) |  |           |  |  Engine   |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |  Guards   |  |CircuitBrkr|  |YAMLParser |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +----------------------------------------------------------------+   |
|  |        OpenSSL-conditional (AIRY_HAS_OPENSSL)               |   |
|  | Signature | Vault | Entitlements | RuntimeProt | NetSec | TLS  |   |
|  +----------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
|                      Syscall layer (atoms/syscall)                    |
+-----------------------------------------------------------------------+

  Request flow:  gateway/daemon → cupolas → [sandbox → permission → sanitize] → atoms/kernel
                                                                  ↓
                                                              audit log
```

**Design principles:** defense-in-depth, zero-trust (default-deny, identity + context per call), full auditability, least privilege, dynamically-extensible guard framework, endogenous security (every layer must pass).

## Upstream Dependencies

> `commons` is the foundation for all agentrt modules; cupolas consumes it directly. cupolas also depends on `atoms` for the enforcement substrate.

| Dependency | Required | Purpose |
|------------|----------|---------|
| **commons** | Yes | Sync primitives, error framework, type definitions (`airy_types.h`), memory management macros (`AIRY_MALLOC`/`FREE`), security/resource utilities — the foundational layer consumed directly |
| **atoms** | Yes | Provides the Syscall surface that cupolas enforces (sandbox, seccomp, capability, 4 protection rings), and the CoreKern IPC primitives (`are_ipc.h`) for the audit queue and workbench IPC |
| OpenSSL | No | Digital signature, key vault, entitlements, runtime protection, TLS — gated by `AIRY_HAS_OPENSSL` |
| libyaml | No | Full YAML support; built-in `yaml_minimal.c` is the fallback |
| cJSON | No | JSON config parsing |

> **BAN-12**: All `find_package` calls are centralized in the umbrella root `CMakeLists.txt`; sub-modules only consume cache variables (`AIRY_HAS_OPENSSL`, `AIRY_HAS_YAML`, `AIRY_HAS_CJSON`).

## Downstream Consumers

| Consumer | What they use |
|----------|---------------|
| **daemons** | Every daemon calls cupolas for permission checks (`cupolas_check_permission`), input sanitization (`cupolas_sanitize_input`), and to emit audit events; the workbench hosts untrusted tool execution (e.g. `tool_d` runs tool commands inside `cupolas_execute_command`) |
| **gateway** | Gateway invokes cupolas for request authentication and input sanitization at the protocol boundary, before translating HTTP/WS/stdio into JSON-RPC |
| External SDK / Agent apps | Use `cupolas_check_permission` and `cupolas_sanitize_input` to participate in the security contract; the safety_guard / zero_trust_integration interfaces let external agents plug into the dome |

## Build

```bash
# Standard build (out-of-source, enforced by BAN-33)
cmake -S . -B /tmp/cupolas-build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build /tmp/cupolas-build --parallel $(nproc)

# Run the test suite (unit / integration / stress / fuzz / benchmark)
ctest --test-dir /tmp/cupolas-build --output-on-failure

# Install
cmake --install /tmp/cupolas-build --prefix /opt/airymax
```

**CMake options:**

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build the test suite (unit / integration / stress / fuzz / benchmark) |
| `BUILD_WITH_SANITIZERS` | `OFF` | Enable ASAN / MSAN / TSAN |
| `BUILD_WITH_LOGGING` | `ON` | Enable verbose logging |
| `AIRY_HAS_OPENSSL` | auto | Auto-detected by umbrella CMake; gates OpenSSL-conditional modules |
| `AIRY_HAS_YAML` | auto | Auto-detected by umbrella CMake |
| `AIRY_HAS_CJSON` | auto | Auto-detected by umbrella CMake |

**Hardened build flags (Linux):** `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fvisibility=hidden`, `-Wl,-z,relro,-z,now`, `-Wl,-z,noexecstack`.

**Build artifacts:**

- `airy_cupolas` — static library aggregating all security subsystems
- Public headers installed under `include/agentrt/cupolas`

## API

Public API surface is exported through `include/cupolas.h` (unified entry) and companion headers `zero_trust_integration.h`, `dynamic_policy_engine.h`, `safety_guard.h`.

| Function | Description |
|----------|-------------|
| `cupolas_init(config_path, error)` | Initialize the cupolas module |
| `cupolas_cleanup()` | Tear down the cupolas module |
| `cupolas_version()` | Get version string |
| `cupolas_check_permission(agent_id, action, resource, context)` | Permission check (1 = allow, 0 = deny) |
| `cupolas_add_permission_rule(agent_id, action, resource, allow, priority)` | Add a permission rule |
| `cupolas_clear_permission_cache()` | Clear the permission cache |
| `cupolas_sanitize_input(input, output, output_size)` | Sanitize input (XSS / SQLi / cmd injection / path traversal) |
| `cupolas_execute_command(command, argv, exit_code, ...)` | Execute a command inside the isolated workbench |
| `cupolas_flush_audit_log()` | Flush the audit log |

The extensible guard framework (`safety_guard.h`) supports rule / model / behavior / heuristic / external / composite / custom guard types. The zero-trust integration interface lets external agents register context providers for identity-and-context-based authorization.

## License

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

This module is dual-licensed under the terms of either:

- **GNU Affero General Public License v3.0 or later**
  ([AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.txt)), or
- **Apache License, Version 2.0**
  ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.txt))

SPDX-License-Identifier: `AGPL-3.0-or-later OR Apache-2.0`

The full license texts are in the [LICENSE](LICENSE) file; the copyright notice is in [NOTICE](NOTICE). You may select either license to comply with. The AGPL-3.0-or-later terms apply by default; the Apache-2.0 alternative is provided for downstream integration scenarios (e.g., closed-source or proprietary distribution) that the AGPL does not accommodate.
