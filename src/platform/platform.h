/* SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd. */
/* SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 */

/*
 * @file platform.h
 * @brief Cross-platform abstraction layer for cupolas - unified entry.
 *
 * 0.1.6 大文件拆分：本文件保留为聚合入口（向后兼容，所有
 * `#include "platform.h"` 无需修改），实际声明按功能域分布到：
 *   - platform_base.h    平台检测 / export / 错误码 / 基础宏
 *   - platform_thread.h  线程 / 互斥锁 / 读写锁 / 条件变量
 *   - platform_process.h 进程 / 管道
 *   - platform_time.h    时间 / 睡眠
 *   - platform_fs.h      文件系统
 *   - platform_mem.h     内存原语
 *   - platform_atomic.h  原子操作
 *   - platform_misc.h    字符串工具
 *   - platform_once.h    一次性初始化
 */

#ifndef cupolas_PLATFORM_H
#define cupolas_PLATFORM_H

#include "platform_base.h"
#include "platform_thread.h"
#include "platform_process.h"
#include "platform_time.h"
#include "platform_fs.h"
#include "platform_mem.h"
#include "platform_atomic.h"
#include "platform_misc.h"
#include "platform_once.h"

#endif /* cupolas_PLATFORM_H */
