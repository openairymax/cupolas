

# =============================================================================
# cupolas — 安全守卫产品装配壳（products 产品仓）
#
# 双模式构建契约（0.1.19 §1.3 机制核外迁；台账 §254c）：
#   embedded   —— agentrt 根 add_subdirectory 纳入本目录时
#                 CMAKE_SOURCE_DIR(=agentrt) ≠ CMAKE_CURRENT_SOURCE_DIR(=本目录)，
#                 下方 preamble 整块跳过；依赖检测、平台宏、合规注入、
#                 commons 目标均由根统一提供（embedded 形态字节不变、零回归）。
#   standalone —— cmake -S products/cupolas -B <出树目录> 产品仓独立
#                 configure/构建/测试；经 AGENTRT_ROOT 复用 agentrt 管理仓的
#                 cmake 模块与 commons 原子件。
# =============================================================================
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.20)

    # AGENTRT_ROOT 三态：-D 缓存变量 → 环境变量 → 默认相对路径
    if(NOT AGENTRT_ROOT)
        if(DEFINED ENV{AGENTRT_ROOT})
            set(AGENTRT_ROOT "$ENV{AGENTRT_ROOT}")
        else()
            set(AGENTRT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../agentrt")
        endif()
    endif()
    get_filename_component(AGENTRT_ROOT "${AGENTRT_ROOT}" ABSOLUTE)
    if(NOT EXISTS "${AGENTRT_ROOT}/commons/CMakeLists.txt")
        message(FATAL_ERROR
            "standalone build requires agentrt commons: AGENTRT_ROOT=${AGENTRT_ROOT} invalid (pass -DAGENTRT_ROOT=<agentrt> or set env AGENTRT_ROOT)")
    endif()

    # 版本 SSoT：承接 agentrt/VERSION（缺失/非法大声失败，镜像根 DT-13 形态）
    file(STRINGS "${AGENTRT_ROOT}/VERSION" AIRY_VERSION_RAW LIMIT_COUNT 1)
    string(STRIP "${AIRY_VERSION_RAW}" AIRY_VERSION_RAW)
    if(NOT AIRY_VERSION_RAW MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+")
        message(FATAL_ERROR "版本 SSoT 非法：VERSION 内容 '${AIRY_VERSION_RAW}' 不符合 X.Y.Z")
    endif()
    string(REGEX REPLACE "([0-9.]+).*" "\\1" AIRY_VERSION_NUM "${AIRY_VERSION_RAW}")
    project(AgentOS-Cupolas VERSION ${AIRY_VERSION_NUM} LANGUAGES C)

    # 源码区内严禁构建：in-source 与构建树嵌于源码树内均 FATAL
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
        message(FATAL_ERROR
            "cupolas in-source builds are not allowed! Use: cmake -S . -B <external-build-dir>")
    endif()
    cmake_path(IS_PREFIX CMAKE_SOURCE_DIR "${CMAKE_BINARY_DIR}" NORMALIZE _CUPOLAS_BIN_IN_SRC)
    if(_CUPOLAS_BIN_IN_SRC)
        message(FATAL_ERROR
            "cupolas build directory MUST be outside the source tree: ${CMAKE_BINARY_DIR}")
    endif()

    if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    endif()

    # 复用 agentrt cmake 模块：平台检测（POSIX 宏与根一致）+ 依赖检测收口
    # （AIRY_HAS_* CACHE）与宏双路下发（airy_compile_defs），单一检测点
    list(APPEND CMAKE_MODULE_PATH "${AGENTRT_ROOT}/cmake")
    include(airy_print)
    include(platform)
    include(dependencies)

    # PkgConfig 顶层自查：函数内 find_package 的 normal 变量不外泄，
    # 下方 body 兜底检测块（目录作用域）读 ${PkgConfig_FOUND} 须于此可见
    find_package(PkgConfig QUIET)

    airy_find_required_deps()
    airy_find_optional_deps()
    airy_detect_platform()
    airy_apply_dep_defs()

    # 版本宏 SSoT 注入（commons airyrt_version.h 消费面）
    add_compile_definitions(AIRYRT_VERSION="${AIRY_VERSION_RAW}")

    # 合规严格模式：镜像根注入面（非 MSVC -include 禁令头；MSVC /FI 强制
    # 预包含）。embedded 下本块整体跳过，由根注入，无双重下发（IRON-8）
    option(AIRY_COMPLIANCE_STRICT "Enable strict compliance mode (poison unsafe functions)" ON)
    if(NOT MSVC)
        if(AIRY_COMPLIANCE_STRICT)
            add_compile_definitions(AIRY_COMPLIANCE_STRICT)
            add_compile_options("-include" "${AGENTRT_ROOT}/commons/utils/compliance/banned_functions.h")
        endif()
    else()
        if(EXISTS "${AGENTRT_ROOT}/cmake/windows_preinclude.h")
            airy_print_ok("[MSVC] Force-include file found: ${AGENTRT_ROOT}/cmake/windows_preinclude.h")
        else()
            airy_print_warn("[MSVC] Force-include file NOT FOUND: ${AGENTRT_ROOT}/cmake/windows_preinclude.h")
        endif()
        add_compile_options(/FI"${AGENTRT_ROOT}/cmake/windows_preinclude.h")
    endif()

    enable_testing()

    # commons 原子件装配（standalone 下 airy_common 唯一创建点）。commons
    # 机制核 tests 的 238 项由 embedded 根树全量覆盖，standalone 不重复承接
    # ——其测试链接 airy_core 等未挂载的 atoms 目标；以 normal 变量阻断其
    # tests 挂载（CMP0077 NEW：option() 让位于先存的 normal 变量）。
    set(BUILD_TESTS OFF)
    add_subdirectory("${AGENTRT_ROOT}/commons" commons)
    unset(BUILD_TESTS)

    # body 断链回退锚：COMMON_MODULE_DIR 指向 agentrt 管理仓内 commons
    set(CUPOLAS_COMMONS_DIR "${AGENTRT_ROOT}/commons")
endif()

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

airy_print_info("[CUPOLAS] Configuring cupolas security module")

option(BUILD_TESTS "Build tests" ON)
option(BUILD_WITH_SANITIZERS "Enable sanitizers (ASAN/MSAN/TSAN)" OFF)
option(BUILD_WITH_LOGGING "Enable detailed logging" ON)

# 使用根级依赖检测结果（单一依赖检测点）
# 所有 find_package 已在根 CMakeLists.txt 中完成，此处仅引用缓存变量。
# YAML 仅在根未检出时兜底自检（libyaml keg-only：根已把 ${YAML_LIBRARIES}
# 提升为绝对路径，重查会覆盖成裸名 "-lyaml"，macOS 链接行再失败）。
if(PkgConfig_FOUND AND NOT YAML_FOUND)
    pkg_check_modules(YAML QUIET libyaml)
endif()
if(PkgConfig_FOUND)
    pkg_check_modules(CJSON QUIET libcjson)
endif()

if(AIRY_HAS_OPENSSL)
    airy_print_ok("Found OpenSSL: ${OpenSSL_VERSION}")
else()
    airy_print_warn("OpenSSL not found, some security features may be limited")
endif()

if(YAML_FOUND OR YAML_LIBRARIES)
    set(HAVE_YAML 1)
    airy_print_ok("Found libyaml: ${YAML_LIBRARIES}")
else()
    set(HAVE_YAML 0)
    airy_print_warn("libyaml not found, YAML manager support disabled")
endif()

if(CJSON_FOUND OR CJSON_LIBRARIES)
    set(HAVE_CJSON 1)
    airy_print_ok("Found libcjson: ${CJSON_LIBRARIES}")
else()
    set(HAVE_CJSON 0)
    airy_print_warn("libcjson not found, JSON support disabled")
endif()

set(CUPOLAS_SOURCES
    src/cupolas.c
    src/utils/cupolas_utils.c
    src/cupolas_metrics.c
    # cupolas_monitoring 按功能域拆分：生命周期/采集与线程/导出/健康检查与端点
    src/cupolas_monitoring.c
    src/cupolas_monitoring_sys.c
    src/cupolas_monitoring_export.c
    src/cupolas_monitoring_service.c
    src/permission/permission_engine.c
    src/permission/permission_rule.c
    src/permission/permission_cache.c
    src/audit/audit_logger.c
    src/audit/audit_queue.c
    src/audit/audit_rotator.c
    src/audit/audit_overflow.c
    src/sanitizer/sanitizer_core.c
    src/sanitizer/sanitizer_rules.c
    src/sanitizer/sanitizer_cache.c
    src/workbench/workbench.c
    src/workbench/workbench_limits.c
    src/security/cupolas_error.c
    src/guards/guard_core.c
    src/guards/guard_integration.c
    # safety_guard 按功能域拆分：生命周期/规则匹配与策略执行/策略管理/配额/审核/回调与紧急停止
    src/guards/safety_guard.c
    src/guards/safety_guard_check.c
    src/guards/safety_guard_policy.c
    src/guards/safety_guard_quota.c
    src/guards/safety_guard_audit.c
    src/guards/safety_guard_ctrl.c
    # 动态策略引擎（版本/冲突消解/热更/回滚，epoch SSoT）
    # 按功能域拆分：核心评估与 CRUD / 版本管理 / JSON 导入导出与两段式生效
    src/policy/dynamic_policy_engine.c
    src/policy/dpolicy_version.c
    src/policy/dpolicy_json.c
)
# OpenSSL-dependent sources
if(AIRY_HAS_OPENSSL)
    list(APPEND CUPOLAS_SOURCES
        src/security/cupolas_signature.c
        src/security/cupolas_vault.c
        src/security/cupolas_vault_credential.c
        src/security/cupolas_vault_access.c
        src/security/cupolas_vault_metadata.c
        src/security/cupolas_vault_rotation.c
        src/security/cupolas_vault_crypto.c
        src/security/cupolas_vault_io.c
        src/security/cupolas_entitlements.c
        src/security/cupolas_entitlements_parse.c
        src/security/cupolas_entitlements_crypto.c
        src/security/cupolas_runtime_protection.c
        src/security/cupolas_runtime_protection_memory.c
        src/security/cupolas_runtime_protection_check.c
        src/security/cupolas_runtime_protection_integrity.c
        # cupolas_network_security 按功能域拆分：生命周期+TLS/防火墙规则/包过滤/连接监控/检测引擎/DNS/工具
        src/security/cupolas_network_security.c
        src/security/cupolas_network_security_firewall.c
        src/security/cupolas_network_security_filter.c
        src/security/cupolas_network_security_conn.c
        src/security/cupolas_network_security_ids.c
        src/security/cupolas_network_security_dns.c
        src/security/cupolas_network_security_util.c
    )
endif()

set(CUPOLAS_HEADERS
    include/cupolas.h
    src/utils/cupolas_utils.h
    src/cupolas_metrics.h
    src/cupolas_monitoring.h
    src/cupolas_monitoring_internal.h
    src/permission/permission.h
    src/permission/permission_engine.h
    src/permission/permission_rule.h
    src/permission/permission_cache.h
    src/audit/audit.h
    src/audit/audit_queue.h
    src/audit/audit_rotator.h
    src/audit/audit_overflow.h
    src/sanitizer/sanitizer.h
    src/sanitizer/sanitizer_rules.h
    src/sanitizer/sanitizer_cache.h
    src/workbench/workbench.h
    src/workbench/workbench_limits.h
    src/security/cupolas_signature.h
    src/security/cupolas_vault.h
    src/security/cupolas_vault_internal.h
    src/security/cupolas_entitlements.h
    src/security/cupolas_entitlements_internal.h
    src/security/cupolas_runtime_protection.h
    src/security/cupolas_runtime_protection_internal.h
    src/security/cupolas_network_security.h
    src/security/cupolas_network_security_internal.h
    src/security/cupolas_error.h
    src/guards/guard_core.h
    src/guards/guard_integration.h
    include/dynamic_policy_engine.h
    src/policy/dpolicy_internal.h
)

# commons 模块路径：embedded 维持根树形态（${CMAKE_SOURCE_DIR}/commons）；
# standalone 由顶部 preamble 置 CUPOLAS_COMMONS_DIR 指向 agentrt 管理仓
if(NOT CUPOLAS_COMMONS_DIR)
    set(CUPOLAS_COMMONS_DIR ${CMAKE_SOURCE_DIR}/commons)
endif()
set(COMMON_MODULE_DIR ${CUPOLAS_COMMONS_DIR})

# commons 模块的 include 目录
set(COMMON_INCLUDE_DIRS
    ${COMMON_MODULE_DIR}/platform/include
    ${COMMON_MODULE_DIR}/utils/include
    # cache_common 原子件：sanitizer/permission 缓存策略复用同一 LRU 存储
    ${COMMON_MODULE_DIR}/utils/cache
    ${COMMON_MODULE_DIR}/utils/error
    ${COMMON_MODULE_DIR}/utils/memory
    ${COMMON_MODULE_DIR}/utils/observability
    ${COMMON_MODULE_DIR}/utils/types
)

add_library(cupolas STATIC ${CUPOLAS_SOURCES} ${CUPOLAS_HEADERS})

if(BUILD_WITH_LOGGING)
    target_compile_definitions(cupolas PRIVATE CUPOLAS_ENABLE_LOGGING=1)
endif()

target_compile_definitions(cupolas PRIVATE
    # 路径默认值由 platform.h 按平台提供（Windows/macOS/Linux），此处
    # 不再无条件覆盖为 /etc/agentrt、/var/log/agentrt（会错误覆盖
    # Windows C:\ProgramData\agentrt 与 macOS 默认路径，跨平台错乱）。
    AIRY_ENABLE_V2_API=1
)

# src 根仅自用，不对外传播；src/security 公共头有 daemon 接线层消费者，
# 保留传播（头迁移至 include/ 待后续线，0.1.19 F4）
target_include_directories(cupolas PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

target_include_directories(cupolas PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    # 安全子模块公共头（vault/entitlements/network/error），供 daemon 接线层裸名 include
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/security>
    $<INSTALL_INTERFACE:include>
    $<INSTALL_INTERFACE:include/cupolas>
)

target_include_directories(cupolas PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    # 版本 SSoT 头（commons/include/airyrt_version.h）：显式声明，避免
    # 依赖 airy_common 的传递性 include 传播（Unify Design：依赖可见）
    ${COMMON_MODULE_DIR}/include
)

target_include_directories(cupolas PUBLIC
    ${COMMON_INCLUDE_DIRS}
)

if(AIRY_HAS_OPENSSL)
    target_include_directories(cupolas PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_compile_definitions(cupolas PRIVATE CUPOLAS_USE_OPENSSL)
endif()

# cupolas 公共头在契约面上暴露 commons 权威类型（airy_types/error/memory），
# airy_common 因此是 PUBLIC 依赖：消费者经其自包含的接口头面解析，不依赖
# 上层目录的全局 include 注入（embedded 根块与 standalone 均经此传承）。
target_link_libraries(cupolas PUBLIC airy_common)

if(AIRY_HAS_OPENSSL)
    target_link_libraries(cupolas PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(YAML_FOUND)
    target_include_directories(cupolas PRIVATE ${YAML_INCLUDE_DIRS})
endif()

if(CJSON_FOUND)
    target_include_directories(cupolas PRIVATE ${CJSON_INCLUDE_DIRS})
endif()

if(MSVC)
    target_link_libraries(cupolas PRIVATE ws2_32 advapi32 psapi)

    target_compile_definitions(cupolas PRIVATE CUPOLAS_BUILDING_DLL)

    target_compile_options(cupolas PRIVATE
        /W4
    )
else()
    target_link_libraries(cupolas PRIVATE Threads::Threads m)

    target_compile_options(cupolas PRIVATE
        -Wall -Wextra -Wpedantic
        -Wformat=2 -Wformat-security
        -fstack-protector-strong
        -fstack-clash-protection
        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
        -fvisibility=hidden
    )

    # 加固链接选项：-Wl,-z,* 为 GNU ld 专有，macOS ld64 报 unknown option，
    # Apple 平台改用 -Wl,-dead_strip（对齐 coreloopthree 写法）。
    if(UNIX AND NOT APPLE)
        target_link_options(cupolas PRIVATE
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )
    elseif(APPLE)
        target_link_options(cupolas PRIVATE -Wl,-dead_strip)
    endif()

    if(BUILD_WITH_SANITIZERS)
        # LSan（leak）仅 Linux 可用：macOS clang 链接期报
        # "unsupported option '-fsanitize=leak'"（对齐顶层 CMakeLists.txt 处理）
        if(APPLE)
            target_compile_options(cupolas PRIVATE
                -fsanitize=address,undefined -fno-omit-frame-pointer
            )
            target_link_options(cupolas PRIVATE -fsanitize=address,undefined)
        else()
            target_compile_options(cupolas PRIVATE
                -fsanitize=address,undefined,leak
                -fno-omit-frame-pointer
            )
            target_link_options(cupolas PRIVATE
                -fsanitize=address,undefined,leak
            )
        endif()
    endif()
endif()

if(YAML_FOUND)
    target_link_libraries(cupolas PRIVATE ${YAML_LIBRARIES})
endif()

if(CJSON_FOUND)
    target_link_libraries(cupolas PRIVATE ${CJSON_LIBRARIES})
endif()

if(BUILD_TESTS)
    enable_testing()

    add_executable(test_cupolas_core tests/unit/test_cupolas_core.c)
    target_compile_definitions(test_cupolas_core PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_core PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_core cupolas)

    # 错误码一致性测试
    # 验证 cupolas enum 与 commons AIRY_ERR_* 宏数值一致、CUPOLAS_* 段
    # 与 SEC_* 段不冲突、各模块错误码段区间互不重叠。该测试仅依赖头文件
    # （cupolas_error.h + error.h），但链接 cupolas 库以覆盖转换函数实现。
    add_executable(test_error_code_consistency tests/unit/test_error_code_consistency.c)
    target_compile_definitions(test_error_code_consistency PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_error_code_consistency PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_error_code_consistency cupolas)

    # INT-11: 四重防护链集成测试（sanitizer → permission → network → audit）
    add_executable(test_cupolas_integration tests/integration/test_cupolas_integration.c)
    target_compile_definitions(test_cupolas_integration PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_integration PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_integration cupolas)

    # 签名/YAML/凭证库测试：与其余单元测试一致使用 AIRY_COMPLIANCE_IMPL
    add_executable(test_cupolas_signature tests/unit/test_cupolas_signature.c)
    target_compile_definitions(test_cupolas_signature PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_signature PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_signature cupolas)

    add_executable(test_yaml_minimal tests/unit/test_yaml_minimal.c)
    target_compile_definitions(test_yaml_minimal PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_yaml_minimal PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
        ${COMMON_MODULE_DIR}/utils/config_unified
    )
    target_link_libraries(test_yaml_minimal cupolas)

    if(AIRY_HAS_OPENSSL)
        add_executable(test_cupolas_vault tests/unit/test_cupolas_vault.c)
        target_compile_definitions(test_cupolas_vault PRIVATE
            AIRY_COMPLIANCE_IMPL AIRY_HAS_OPENSSL=1)
        target_include_directories(test_cupolas_vault PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${COMMON_INCLUDE_DIRS}
        )
        target_link_libraries(test_cupolas_vault cupolas)
    endif()

    if(MSVC)
        add_custom_command(TARGET test_cupolas_core POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:cupolas>
                $<TARGET_FILE_DIR:test_cupolas_core>)
    endif()

    add_test(NAME cupolas_core_tests COMMAND test_cupolas_core)
    add_test(NAME error_code_consistency_tests COMMAND test_error_code_consistency)

    # PEP：cupolas_init_pep 语义单测——不构造本地
    # permission 引擎（策略由 PDP cupolas_d 持有），sanitizer 层保留
    add_executable(test_cupolas_pep_init tests/unit/test_cupolas_pep_init.c)
    target_compile_definitions(test_cupolas_pep_init PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_pep_init PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_pep_init cupolas)
    add_test(NAME cupolas_pep_init_tests COMMAND test_cupolas_pep_init)
    add_test(NAME cupolas_integration_tests COMMAND test_cupolas_integration)
    add_test(NAME cupolas_signature_tests COMMAND test_cupolas_signature)
    add_test(NAME cupolas_yaml_tests COMMAND test_yaml_minimal)
    if(AIRY_HAS_OPENSSL)
        add_test(NAME cupolas_vault_tests COMMAND test_cupolas_vault)
    endif()

    # DP 引擎单元测试
    # 需要 AIRY_ENABLE_V2_API 暴露 dpolicy_* API；cJSON 用于 JSON 往返断言
    add_executable(test_dynamic_policy_engine tests/unit/test_dynamic_policy_engine.c)
    target_compile_definitions(test_dynamic_policy_engine PRIVATE
        AIRY_COMPLIANCE_IMPL AIRY_ENABLE_V2_API=1)
    target_include_directories(test_dynamic_policy_engine PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
        ${CJSON_INCLUDE_DIRS}
    )
    target_link_libraries(test_dynamic_policy_engine cupolas ${CJSON_LIBRARIES})
    add_test(NAME cupolas_dpolicy_engine_tests COMMAND test_dynamic_policy_engine)

    # L1-B 接线：四重防护链独立集成测试（INT-11 全链，tests/ 根）
    add_executable(test_protection_chain tests/test_protection_chain.c)
    target_compile_definitions(test_protection_chain PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_protection_chain PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_protection_chain cupolas)
    add_test(NAME protection_chain_tests COMMAND test_protection_chain)

    # L1-B 接线：审计溢出防护单测
    add_executable(test_audit_overflow tests/unit/test_audit_overflow.c)
    target_compile_definitions(test_audit_overflow PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_audit_overflow PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/audit
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_audit_overflow cupolas)
    add_test(NAME audit_overflow_tests COMMAND test_audit_overflow)

    # L1-B 接线：sanitizer 缓存单测
    add_executable(test_sanitizer_cache tests/unit/test_sanitizer_cache.c)
    target_compile_definitions(test_sanitizer_cache PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_sanitizer_cache PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sanitizer
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_sanitizer_cache cupolas)
    add_test(NAME sanitizer_cache_tests COMMAND test_sanitizer_cache)

    # L1-B 接线：安全模块（entitlements/network/runtime/signature/vault）单测
    add_executable(test_cupolas_security tests/unit/test_cupolas_security.c)
    target_compile_definitions(test_cupolas_security PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_security PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_security cupolas)
    add_test(NAME cupolas_security_tests COMMAND test_cupolas_security)

    # 并发压力金丝雀：64 线程×10K 权限检查，非断言型（仅崩溃/挂死判失败）。
    # RUN_SERIAL 隔离资源争抢，TIMEOUT 兜底无限挂起。
    add_executable(test_stress_concurrent tests/stress/test_stress_concurrent.c)
    target_compile_definitions(test_stress_concurrent PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_stress_concurrent PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_stress_concurrent cupolas Threads::Threads)
    add_test(NAME cupolas_stress_concurrent COMMAND test_stress_concurrent)
    set_tests_properties(cupolas_stress_concurrent PROPERTIES
        RUN_SERIAL TRUE TIMEOUT 300)

    # 权限检查延迟 p50/p99 + PEP 缓存命中率基线。
    # 非断言型基准（性能观测用），默认跳过；--run-benchmark 参数显式运行。
    add_executable(benchmark_permission tests/benchmark/benchmark_permission.c)
    target_include_directories(benchmark_permission PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(benchmark_permission cupolas)
    add_test(NAME cupolas_benchmark_permission COMMAND benchmark_permission 20000)
    set_tests_properties(cupolas_benchmark_permission PROPERTIES RUN_SERIAL TRUE)
endif()

install(TARGETS cupolas
    EXPORT cupolas-targets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)

# install(EXPORT cupolas-targets
#     FILE cupolas-targets.cmake
#     DESTINATION lib/cmake
# )

install(FILES ${CUPOLAS_HEADERS}
    DESTINATION include/cupolas
)

install(FILES include/cupolas.h
    DESTINATION include
)
