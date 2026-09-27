# Sanitizer — 输入清洗器

**模块路径**: `agentrt/cupolas/src/sanitizer/`

## 概述

Sanitizer 模块提供全面的输入清洗和注入防护能力，是 Cupolas 安全穹顶的第一道防线。覆盖 XSS（跨站脚本）、SQL 注入、命令注入和路径遍历四种主要攻击向量，支持规则引擎和缓存机制，确保所有外部输入在进入系统前经过严格清洗。

## 设计目标

- **全面防护**：覆盖 XSS、SQL 注入、命令注入、路径遍历四类危险字符
- **分级执行**：NONE/LOW/MEDIUM/HIGH/MAX 五级策略，按场景选择转义或拒绝
- **规则引擎**：可配置的字面量规则，支持自定义规则扩展
- **高性能缓存**：清洗结果按输入与级别缓存，避免重复计算
- **fail-closed**：异常路径（无 replacement 规则、缓冲区不足、内存失败）一律收紧而非放行

## 目录结构

```
sanitizer/
├── sanitizer.h                  # 清洗器公共接口
├── sanitizer_core.c             # 清洗核心引擎实现
├── sanitizer_rules.h            # 规则引擎接口
├── sanitizer_rules.c            # 规则管理实现
├── sanitizer_cache.h            # 清洗缓存接口
├── sanitizer_cache.c            # 缓存实现
└── README.md                    # 本文档
```

## 净化级别

净化级别由 `sanitize_level.h`（commons SSoT）唯一定义，强度递增，`level` 可直接数值比较。
权威来源：`docs/AirymaxRT/07-subsystem-specs/04-cupolas.md §4.3`。

| 级别 | 值 | 执行策略 |
|------|------|------|
| `SANITIZE_LEVEL_NONE` | 0 | 不净化，输入原样透传（仍受 `max_length` 约束） |
| `SANITIZE_LEVEL_LOW` | 1 | 危险字符转义（字符类由 `allow_*` 决定） |
| `SANITIZE_LEVEL_MEDIUM` | 2 | 转义 + 自定义规则阶段（默认级别） |
| `SANITIZE_LEVEL_HIGH` | 3 | 白名单模式，非白名单输入直接拒绝 |
| `SANITIZE_LEVEL_MAX` | 4 | 拒绝全部输入 |

`sanitize_context_t.level` 缺省为 `SANITIZE_LEVEL_MEDIUM`（`sanitizer_default_context`）。
`sanitizer_is_safe` 与 `sanitizer_sanitize` 采用同一级别语义：MAX 恒不安全；NONE 恒安全；
HIGH/MAX 走白名单判定；LOW/MEDIUM 检查危险字符。

## 净化语义

净化结果只会是**转义**或**拒绝**，从不静默删除文本。因此转义后的输出仍可能包含
`onerror`、`DROP TABLE` 等字样——防护目标是消除**未转义的危险元字符**，
而非移除关键词。判定其中的字符类：

| 字符类 | 触发字符 | 受控开关 |
|--------|----------|----------|
| HTML | `<` `>` `&` | `allow_html` |
| SQL | `'` `"` `;` | `allow_sql` |
| Shell | `\|` `&` `$` `` ` `` `(` `)` `{` `}` | `allow_shell` |
| 路径 | `\`、连续 `..` | `allow_path` |
| 控制字符 | `< 0x20`（除 `\t` `\n` `\r`） | 无（恒拒绝） |

字符类危险判定与级别解耦：`level` 选择执行策略（转义 / 白名单 / 拒绝），
`allow_*` 选择可接受字符类。

### 转义策略

| 字符类 | 转义形式 |
|--------|----------|
| HTML | `<`→`&lt;`、`>`→`&gt;`、`&`→`&amp;` |
| SQL | `'`→`''` |
| Shell | 前导反斜杠（`\` + 字符） |
| 兜底 | 缓冲区不足以容纳转义序列时降级为 `?` |
| 专用 API | `sanitizer_escape_html` 额外处理 `"`→`&quot;`、`'`→`&#39;`；`sanitizer_escape_shell` / `sanitizer_escape_path` 使用 `\xNN` / `%NN` 编码 |

### HIGH 白名单

`SANITIZE_LEVEL_HIGH` 仅放行可打印 ASCII：字母数字、空白（空格 / `\t` / `\n` / `\r`），
以及 `. , : ; _ @ # - + / = ? ! ( )`。引号、HTML/Shell 元字符、控制字符、
非 ASCII 字节（`>= 0x80`）以及集合外任意字节一律拒绝。

### 自定义规则（MEDIUM 阶段）

`sanitizer_add_rule(san, pattern, replacement)` 添加**字面量子串**匹配规则
（非正则）。MEDIUM 级别在字符转义之后执行规则阶段：

- 命中且 `replacement` 非空：整段替换为 `replacement`
- 命中且 `replacement` 为 NULL：**fail-closed 整体拒绝**（`SANITIZE_REJECTED`）
- 规则阶段内存分配失败：`SANITIZE_ERROR`

## 接口说明

### 核心清洗 API

| 函数 | 说明 |
|------|------|
| `sanitizer_create(rules_path)` | 创建清洗器实例（rules_path 可为 NULL） |
| `sanitizer_destroy(sanitizer)` | 销毁清洗器实例 |
| `sanitizer_sanitize(sanitizer, input, output, output_size, ctx)` | 执行清洗（返回 `sanitize_result_t`） |
| `sanitizer_is_safe(sanitizer, input, ctx)` | 检查输入是否安全（返回 `bool`） |

### 转义 API

| 函数 | 说明 |
|------|------|
| `sanitizer_escape_html(input, output, output_size)` | HTML 特殊字符转义 |
| `sanitizer_escape_sql(input, output, output_size)` | SQL 特殊字符转义 |
| `sanitizer_escape_shell(input, output, output_size)` | Shell 特殊字符转义 |
| `sanitizer_escape_path(input, output, output_size)` | 路径特殊字符转义 |

### 规则与配置 API

| 函数 | 说明 |
|------|------|
| `sanitizer_add_rule(sanitizer, pattern, replacement)` | 添加自定义规则（replacement 为 NULL 则拒绝） |
| `sanitizer_clear_rules(sanitizer)` | 清除所有自定义规则（保留默认规则） |
| `sanitizer_default_context(ctx)` | 获取默认清洗上下文 |

### sanitize_result_t — 清洗结果

| 枚举值 | 说明 |
|--------|------|
| `SANITIZE_OK` | 通过清洗，内容未修改 |
| `SANITIZE_MODIFIED` | 通过清洗，内容已修改 |
| `SANITIZE_REJECTED` | 拒绝，检测到威胁 |
| `SANITIZE_ERROR` | 清洗过程出错 |

### sanitize_context_t — 清洗上下文

| 字段 | 类型 | 说明 |
|------|------|------|
| `agent_id` | `const char *` | Agent 标识 |
| `input_type` | `const char *` | 输入类型 |
| `level` | `sanitize_level_t` | 清洗级别（见「净化级别」，缺省 `MEDIUM`） |
| `max_length` | `size_t` | 最大输入长度 |
| `allow_html` | `bool` | 是否允许 HTML |
| `allow_sql` | `bool` | 是否允许 SQL |
| `allow_shell` | `bool` | 是否允许 Shell |
| `allow_path` | `bool` | 是否允许路径 |

## 使用示例

```c
#include "sanitizer.h"

sanitizer_t *san = sanitizer_create(NULL);

char output[4096];
sanitize_result_t result = sanitizer_sanitize(
    san, "<script>alert('xss')</script>", output, sizeof(output), NULL);

if (result == SANITIZE_OK) {
    printf("Clean output: %s\n", output);
} else if (result == SANITIZE_MODIFIED) {
    printf("Modified output: %s\n", output);
} else if (result == SANITIZE_REJECTED) {
    printf("Input rejected\n");
}

/* 专用转义函数 */
char escaped[4096];
sanitizer_escape_html("<b>bold</b>", escaped, sizeof(escaped));
sanitizer_escape_sql("1' OR '1'='1", escaped, sizeof(escaped));
sanitizer_escape_shell("ls; rm -rf /", escaped, sizeof(escaped));
sanitizer_escape_path("../../../etc/passwd", escaped, sizeof(escaped));

/* 安全检查 */
bool safe = sanitizer_is_safe(san, user_input, NULL);

/* 自定义规则 */
sanitizer_add_rule(san, "pattern.*match", "replacement");

sanitizer_destroy(san);
```

## 清洗缓存

| 参数 | 默认值 | 说明 |
|------|--------|------|
| max_entries | 1024 | 最大缓存条目数 |
| ttl_seconds | 300 | 缓存 TTL（秒） |
| eviction_policy | LRU | 淘汰策略 |

缓存命中时清洗时间 < 100ns，缓存未命中时取决于输入长度和规则数量。

## 依赖关系

| 依赖 | 说明 |
|------|------|
| `platform.h` | 平台抽象层 |
| `cupolas_utils.h` | 安全内存管理、日志宏 |
| `sanitize_level.h` | 清洗级别类型定义（来自 commons） |

## 相关子系统

| 子系统 | 关系 |
|--------|------|
| [Permission](../permission/README.md) | 清洗通过后进入权限检查 |
| [Audit](../audit/README.md) | 清洗拒绝事件记录审计日志 |
| [Workbench](../workbench/README.md) | 工作台执行前对命令进行清洗 |
| [Security](../security/README.md) | 安全引擎调用清洗器进行输入校验 |

---

© 2025-2026 SPHARX Ltd. All Rights Reserved.
