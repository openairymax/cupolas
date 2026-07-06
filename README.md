**Language:** English | [简体中文](README_zh.md)

# Airymax Cupolas — Security Dome

`agentrt/cupolas/`

**Version:** 0.1.1
**License:** AGPL-3.0-or-later OR Apache-2.0 (dual-licensed)
**Branch:** `feature/official-hubs-01`

---

## 1. Module Positioning

Cupolas (literally "dome") is the **application-semantic security layer** (B-tier)
of the Airymax agent runtime. It is the umbrella under which every runtime
security decision is made and enforced. Cupolas implements a four-layer
endogenous-security model — every layer must be passed before an agent action
reaches the kernel:

1. **Sandbox isolation** — every untrusted task runs in a confined workbench
   (process / container isolation with resource limits).
2. **RBAC permission adjudication** — every action is checked against an
   RBAC + ABAC permission engine with rule-priority ordering and a
   permission cache.
3. **Input sanitization** — every input is scrubbed for XSS, SQL injection,
   command injection, and path traversal before it touches an executor.
4. **Audit tracing** — every security event is written to an asynchronous,
   HMAC-signed, rotating audit log for forensic traceability.

Cupolas follows defense-in-depth and zero-trust principles: default-deny,
identity-and-context-based authorization per call, full auditability, least
privilege, and a dynamically-extensible guard framework.

---

## 2. Directory Structure

```
cupolas/
├── CMakeLists.txt                        # CMake build configuration
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

### Core Subsystems

| Subsystem | Path | Responsibility |
|-----------|------|----------------|
| **Input Sanitizer** | `src/sanitizer/` | XSS / SQL injection / command injection / path traversal defense |
| **Permission** | `src/permission/` | RBAC + ABAC engine, rule-priority ordering, cache |
| **Audit** | `src/audit/` | Async writes, HMAC signature chain, log rotation |
| **Security Engine** | `src/security/` | Digital signature, key vault, entitlements, runtime protection, network security |
| **Workbench** | `src/workbench/` | Isolated execution, resource control, process management |
| **Guards** | `src/guards/` | Extensible detection framework (rule / model / behavior / heuristic / external / composite / custom) |
| **Utils** | `src/utils/` | Memory mgmt, error handling, logging, compiler hints, bit ops, time |

### OpenSSL-conditional modules

When `AGENTRT_HAS_OPENSSL` is defined, the following iOS-grade security modules
are enabled:

| Module | Source | Responsibility |
|--------|--------|----------------|
| **Digital Signature** | `cupolas_signature.c` | RSA/ECDSA/Ed25519 verification, certificate chain, integrity |
| **Key Vault** | `cupolas_vault.c` | AES-256-GCM credential storage, ACL, rotation |
| **Entitlements** | `cupolas_entitlements.c` | Declarative permissions (FS / network / IPC / vault / quota / syscall / capability) |
| **Runtime Protection** | `cupolas_runtime_protection.c` | seccomp, CFI, memory protection, integrity checks |
| **Network Security** | `cupolas_network_security.c` | TLS connection mgmt, firewall rules, cert verification |
| **TLS Security** | `network/tls_security.c` | TLS/SSL connection management and cert verification |

---

## 3. Upstream / Downstream Dependencies

### Upstream (Cupolas depends on)

| Dependency | Required | Purpose |
|------------|----------|---------|
| **commons** | Yes | Sync primitives, error framework, type definitions, memory management macros — Cupolas consumes the foundational layer directly |
| **atoms** | Yes | Provides the Syscall surface that Cupolas enforces (sandbox, seccomp, capability), and the CoreKern IPC primitives for the audit queue |
| OpenSSL | No | Digital signature, key vault, TLS — gated by `AGENTRT_HAS_OPENSSL` |
| libyaml | No | Full YAML support; built-in `yaml_minimal.c` is the fallback |
| cJSON | No | JSON config parsing |

> **BAN-12**: All `find_package` calls are centralized in the umbrella root
> `CMakeLists.txt`; sub-modules only consume cache variables.

### Downstream (consumers of Cupolas)

| Consumer | What it uses |
|----------|--------------|
| **daemons** | Every daemon calls Cupolas for permission checks, input sanitization, and to emit audit events; the workbench hosts untrusted tool execution |
| **gateway** | Gateway invokes Cupolas for request authentication and input sanitization at the protocol boundary |
| External SDK / Agent apps | Use `cupolas_check_permission` and `cupolas_sanitize_input` to participate in the security contract |

---

## 4. Public API (`cupolas.h`)

| Function | Description |
|----------|-------------|
| `cupolas_init(config_path, error)` | Initialize the Cupolas module |
| `cupolas_cleanup()` | Tear down the Cupolas module |
| `cupolas_version()` | Get version string |
| `cupolas_check_permission(agent_id, action, resource, context)` | Permission check (1 = allow, 0 = deny) |
| `cupolas_add_permission_rule(agent_id, action, resource, allow, priority)` | Add a permission rule |
| `cupolas_clear_permission_cache()` | Clear the permission cache |
| `cupolas_sanitize_input(input, output, output_size)` | Sanitize input |
| `cupolas_execute_command(command, argv, exit_code, ...)` | Execute a command inside the isolated workbench |
| `cupolas_flush_audit_log()` | Flush the audit log |

### Architecture Overview

```
+-----------------------------------------------------------------------+
|                   Security Assurance System (Cupolas)                 |
+-----------------------------------------------------------------------+
|  +-----------+  +-----------+  +-----------+                          |
|  | Workbench |  | Sanitizer |  | Permission|   (4 endogenous layers)  |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |   Audit   |  |   Utils   |  |  Security |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +-----------+  +-----------+  +-----------+                          |
|  |  Guards   |  |CircuitBrkr|  |YAMLParser |                          |
|  +-----------+  +-----------+  +-----------+                          |
|  +----------------------------------------------------------------+   |
|  |        OpenSSL-conditional (AGENTRT_HAS_OPENSSL)               |   |
|  | Signature | Vault | Entitlements | RuntimeProt | NetSec | TLS  |   |
|  +----------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
|                      Syscall layer (atoms/syscall)                    |
+-----------------------------------------------------------------------+
```

---

## 5. Build Instructions

```bash
# Standard build (from the umbrella root, or standalone)
cmake -B build -DBUILD_TESTS=ON -DBUILD_WITH_SANITIZERS=OFF
cmake --build build

# Run the test suite (unit / integration / stress / fuzz / benchmark)
ctest --test-dir build
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build the test suite (unit / integration / stress / fuzz / benchmark) |
| `BUILD_WITH_SANITIZERS` | `OFF` | Enable ASAN / MSAN / TSAN |
| `BUILD_WITH_LOGGING` | `ON` | Enable verbose logging |
| `AGENTRT_HAS_OPENSSL` | auto | Auto-detected by umbrella CMake; gates OpenSSL-conditional modules |
| `AGENTRT_HAS_YAML` | auto | Auto-detected by umbrella CMake |
| `AGENTRT_HAS_CJSON` | auto | Auto-detected by umbrella CMake |

### Hardened build flags (Linux)

- `-fstack-protector-strong` — stack protection
- `-D_FORTIFY_SOURCE=2` — buffer-overflow protection
- `-fvisibility=hidden` — symbol hiding
- `-Wl,-z,relro,-z,now` — read-only relocations
- `-Wl,-z,noexecstack` — non-executable stack

### Build Artifacts

- `agentrt_cupolas` — static library aggregating all security subsystems
- Public headers installed under `include/agentrt/cupolas`

### Installation

```bash
cmake --install build --prefix /opt/airymax
```

---

## 6. License

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

This module is dual-licensed under the terms of either:

- **GNU Affero General Public License v3.0 or later**
  ([AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.txt)), or
- **Apache License, Version 2.0**
  ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0.txt))

SPDX-License-Identifier: `AGPL-3.0-or-later OR Apache-2.0`

The full license texts are in the [LICENSE](LICENSE) file; the copyright
notice is in [NOTICE](NOTICE). You may select either license to comply with.
The AGPL-3.0-or-later terms apply by default; the Apache-2.0 alternative is
provided for downstream integration scenarios (e.g., closed-source or
proprietary distribution) that the AGPL does not accommodate.
