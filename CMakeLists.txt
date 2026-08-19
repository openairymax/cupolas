

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

airy_print_info("[CUPOLAS] Configuring cupolas security module")

option(BUILD_TESTS "Build tests" ON)
option(BUILD_WITH_SANITIZERS "Enable sanitizers (ASAN/MSAN/TSAN)" OFF)
option(BUILD_WITH_LOGGING "Enable detailed logging" ON)

# 使用根级依赖检测结果 (BAN-12: 单一依赖检测点)
# 所有 find_package 已在根 CMakeLists.txt 中完成，此处仅引用缓存变量

if(PkgConfig_FOUND)
    pkg_check_modules(YAML QUIET libyaml)
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
    # cupolas platform 按功能域拆分：同步原语/进程与管道/时间/文件系统/内存与原子/错误与字符串
    src/platform/platform.c
    src/platform/platform_process.c
    src/platform/platform_time.c
    src/platform/platform_fs.c
    src/platform/platform_mem.c
    src/platform/platform_util.c
    src/platform/sandbox.c
    src/utils/cupolas_utils.c
    src/cupolas_metrics.c
    src/cupolas_config.c
    src/cupolas_monitoring.c
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
    src/security/network/http_security.c
    src/security/network/dns_security.c
    src/security/network/network_filter.c
    src/security/network/network_utils.c
    src/guards/guard_core.c
    src/guards/guard_integration.c
    # safety_guard 按功能域拆分：生命周期/规则匹配与策略执行/策略管理/配额/审核/回调与紧急停止
    src/guards/safety_guard.c
    src/guards/safety_guard_check.c
    src/guards/safety_guard_policy.c
    src/guards/safety_guard_quota.c
    src/guards/safety_guard_audit.c
    src/guards/safety_guard_ctrl.c
    src/circuit_breaker.c
    src/slab.c
    src/mempool.c
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
        src/security/cupolas_runtime_protection.c
        # cupolas_network_security 按功能域拆分：生命周期+TLS/防火墙规则/包过滤/连接监控/检测引擎/DNS/工具
        src/security/cupolas_network_security.c
        src/security/cupolas_network_security_firewall.c
        src/security/cupolas_network_security_filter.c
        src/security/cupolas_network_security_conn.c
        src/security/cupolas_network_security_ids.c
        src/security/cupolas_network_security_dns.c
        src/security/cupolas_network_security_util.c
        src/security/network/tls_security.c
    )
endif()

set(CUPOLAS_HEADERS
    include/cupolas.h
    src/utils/cupolas_utils.h
    src/cupolas_metrics.h
    src/cupolas_config.h
    src/cupolas_monitoring.h
    src/platform/platform.h
    src/platform/sandbox.h
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
    src/workbench/workbench_process.h
    src/workbench/workbench_limits.h
    src/security/cupolas_signature.h
    src/security/cupolas_vault.h
    src/security/cupolas_vault_internal.h
    src/security/cupolas_entitlements.h
    src/security/cupolas_runtime_protection.h
    src/security/cupolas_network_security.h
    src/security/cupolas_network_security_internal.h
    src/security/cupolas_error.h
    src/security/network/tls_security.h
    src/security/network/http_security.h
    src/security/network/dns_security.h
    src/security/network/network_filter.h
    src/security/network/network_utils.h
    src/guards/guard_core.h
    src/guards/guard_integration.h
    src/circuit_breaker.h
    src/slab.h
    src/mempool.h
)

# commons 模块路径
set(COMMON_MODULE_DIR ${CMAKE_SOURCE_DIR}/commons)

# commons 模块的 include 目录
set(COMMON_INCLUDE_DIRS
    ${COMMON_MODULE_DIR}/platform/include
    ${COMMON_MODULE_DIR}/utils/include
    ${COMMON_MODULE_DIR}/utils/error/include
    ${COMMON_MODULE_DIR}/utils/memory/include
    ${COMMON_MODULE_DIR}/utils/observability/include
    ${COMMON_MODULE_DIR}/utils/types/include
)

add_library(cupolas STATIC ${CUPOLAS_SOURCES} ${CUPOLAS_HEADERS})

# 豁免内存子系统实现层：mempool.c 和 slab.c 实现底层内存管理，
# 必须使用底层 malloc/calloc/memset，需定义 AIRY_COMPLIANCE_IMPL 跳过 poison
if(AIRY_COMPLIANCE_STRICT)
    set_source_files_properties(
        src/mempool.c
        src/slab.c
        PROPERTIES COMPILE_DEFINITIONS AIRY_COMPLIANCE_IMPL
    )
endif()

if(BUILD_WITH_LOGGING)
    target_compile_definitions(cupolas PRIVATE CUPOLAS_ENABLE_LOGGING=1)
endif()

target_compile_definitions(cupolas PRIVATE
    AIRY_CONFIG_DIR="/etc/agentrt"
    AIRY_LOG_DIR="/var/log/agentrt"
    AIRY_ENABLE_V2_API=1
)

target_include_directories(cupolas PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    # 安全子模块公共头（vault/entitlements/network/error），供 daemon 接线层裸名 include
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/security>
    $<INSTALL_INTERFACE:include>
    $<INSTALL_INTERFACE:include/cupolas>
)

target_include_directories(cupolas PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_include_directories(cupolas PUBLIC
    ${COMMON_INCLUDE_DIRS}
)

if(AIRY_HAS_OPENSSL)
    target_include_directories(cupolas PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_compile_definitions(cupolas PRIVATE CUPOLAS_USE_OPENSSL)
endif()

target_link_libraries(cupolas PRIVATE airy_common)

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

    # P0.25.6 (ACC-STD06): 错误码一致性测试
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

    # S-7 (0.1.2): 原生沙箱（Landlock + seccomp）单元测试。
    # 内核不支持 Landlock 时 enabled 用例自动 SKIP，不误报失败。
    add_executable(test_sandbox tests/unit/test_sandbox.c)
    target_compile_definitions(test_sandbox PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_sandbox PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_sandbox cupolas)

    # INT-11: 四重防护链集成测试（sanitizer → permission → network → audit）
    add_executable(test_cupolas_integration tests/integration/test_cupolas_integration.c)
    target_compile_definitions(test_cupolas_integration PRIVATE AIRY_COMPLIANCE_IMPL)
    target_include_directories(test_cupolas_integration PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${COMMON_INCLUDE_DIRS}
    )
    target_link_libraries(test_cupolas_integration cupolas)

    # test_stress_concurrent disabled: 压力测试非单元测试，单独手动运行

    # 签名/压力/YAML/凭证库测试：与其余单元测试一致使用 AIRY_COMPLIANCE_IMPL
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
        ${COMMON_MODULE_DIR}/utils/config_unified/include
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
    add_test(NAME sandbox_tests COMMAND test_sandbox)
    add_test(NAME cupolas_integration_tests COMMAND test_cupolas_integration)
    add_test(NAME cupolas_signature_tests COMMAND test_cupolas_signature)
    add_test(NAME cupolas_yaml_tests COMMAND test_yaml_minimal)
    if(AIRY_HAS_OPENSSL)
        add_test(NAME cupolas_vault_tests COMMAND test_cupolas_vault)
    endif()
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
