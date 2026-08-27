// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/**
 * @file cupolas_runtime_protection_memory.c
 * @brief Enhanced Runtime Protection - memory protection domain: ASLR / DEP
 *        hardening, memory locking, page protection and protected allocation
 *        (functional domain after cupolas_runtime_protection.c split).
 * @author SPHARX Ltd. - Airymax Team
 * @date 2026
 */

#include "cupolas_runtime_protection.h"
#include "cupolas_runtime_protection_internal.h"

#include "airy_memory.h"

#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#else
#include "airy_mman.h"

#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#include "error.h"

int cupolas_memory_protect_enable(const cupolas_memory_protect_config_t *manager)
{
    if (!manager)
        return AIRY_EINVAL;

#ifdef __linux__
    if (manager->enable_aslr) {
        int fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
        if (fd >= 0) {
            char buf[8] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0 && buf[0] != '2' && buf[0] != '1') {
                fd = open("/proc/sys/kernel/randomize_va_space", O_WRONLY);
                if (fd >= 0) {
                    ssize_t wr = write(fd, "2", 1);
                    (void)wr;
                    close(fd);
                }
            }
        }
    }

    if (manager->enable_stack_protector) {
#ifdef PR_SET_PTRACER
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    }
#endif

#ifdef _WIN32
    if (manager->enable_aslr) {
        HANDLE hProc = GetCurrentProcess();
        SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
    }
#endif

    return 0;
}

int cupolas_memory_lock(void *addr, size_t len)
{
    if (!addr || len == 0)
        return AIRY_EINVAL;

#ifdef _WIN32
    return VirtualLock(addr, len) ? 0 : -1;
#elif defined(__linux__) || defined(__APPLE__)
    return mlock(addr, len);
#else
    return AIRY_EINVAL;
#endif
}

int cupolas_memory_unlock(void *addr, size_t len)
{
    if (!addr || len == 0)
        return AIRY_EINVAL;

#ifdef _WIN32
    return VirtualUnlock(addr, len) ? 0 : -1;
#elif defined(__linux__) || defined(__APPLE__)
    return munlock(addr, len);
#else
    return AIRY_EINVAL;
#endif
}

int cupolas_memory_protect(void *addr, size_t len, int prot)
{
    if (!addr || len == 0)
        return AIRY_EINVAL;

#ifdef _WIN32
    DWORD old_prot;
    DWORD new_prot = 0;

    if (prot & 0x1)
        new_prot |= PAGE_READONLY;
    if (prot & 0x2)
        new_prot |= PAGE_READWRITE;
    if (prot & 0x4)
        new_prot |= PAGE_EXECUTE_READ;
    if ((prot & 0x6) == 0x6)
        new_prot = PAGE_EXECUTE_READWRITE;

    return VirtualProtect(addr, len, new_prot, &old_prot) ? 0 : -1;
#elif defined(__linux__) || defined(__APPLE__)
    return mprotect(addr, len, prot);
#else
    (void)prot;
    return AIRY_EINVAL;
#endif
}

void *cupolas_memory_alloc_protected(size_t size, int prot)
{
    if (size == 0)
        return NULL;

#ifdef _WIN32
    DWORD prot_flags = PAGE_READWRITE;
    if (prot & 0x4)
        prot_flags = PAGE_EXECUTE_READWRITE;

    void *ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, prot_flags);
    return ptr;
#elif defined(__linux__) || defined(__APPLE__)
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *ptr = mmap(NULL, size, prot, flags, -1, 0);
    return (ptr == MAP_FAILED) ? NULL : ptr;
#else
    (void)prot;
    return AIRY_MALLOC(size);
#endif
}

void cupolas_memory_free_protected(void *ptr)
{
    if (!ptr)
        return;

#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#elif defined(__linux__) || defined(__APPLE__)
    munmap(ptr, 4096);
#else
    AIRY_FREE(ptr);
#endif
}
