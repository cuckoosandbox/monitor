/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2015 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <windows.h>
#include "ntapi.h"
#include "pipe.h"

static HANDLE g_current_process;

static NTSTATUS (WINAPI *pNtQueryVirtualMemory)(HANDLE ProcessHandle,
    VOID *BaseAddress, ULONG MemoryInformationClass,
    VOID *MemoryInformation, SIZE_T MemoryInformationLength,
    SIZE_T *ReturnLength);

static NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle,
    VOID **BaseAddress, ULONG_PTR ZeroBits, SIZE_T *RegionSize,
    ULONG AllocationType, ULONG Protect);

static NTSTATUS (WINAPI *pNtProtectVirtualMemory)(HANDLE ProcessHandle,
    VOID **BaseAddress, ULONG *NumberOfBytesToProtect,
    ULONG NewAccessProtection, ULONG *OldAccessProtection);

static uint32_t (WINAPI *pRtlGetLastWin32Error)();
static void (WINAPI *pRtlSetLastWin32Error)(uint32_t error_value);

static const char *g_funcnames[] = {
    "NtQueryVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "RtlGetLastWin32Error",
    "RtlSetLastWin32Error",
    NULL,
};

static void **g_pointers[] = {
    (void **) &pNtQueryVirtualMemory,
    (void **) &pNtAllocateVirtualMemory,
    (void **) &pNtProtectVirtualMemory,
    (void **) &pRtlGetLastWin32Error,
    (void **) &pRtlSetLastWin32Error,
};

int native_init()
{
    g_current_process = GetCurrentProcess();

    uint8_t *memory = VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(memory == NULL) return -1;

    for (uint32_t idx = 0; g_funcnames[idx] != NULL; idx++) {
        *g_pointers[idx] = memory;
        memory += 64;

        FARPROC fp = GetProcAddress(
            GetModuleHandle("ntdll"), g_funcnames[idx]);
        if(fp == NULL) {
            pipe("CRITICAL:Error retrieving address of %z!",
                g_funcnames[idx]);
            continue;
        }

        memcpy(*g_pointers[idx], fp, 64);
    }

    unsigned long old_protect;
    VirtualProtect(*g_pointers[0], 0x1000, PAGE_EXECUTE_READ, &old_protect);
    return 0;
}

int virtual_query_ex(HANDLE process_handle, void *addr,
    MEMORY_BASIC_INFORMATION *mbi)
{
    SIZE_T return_length;
    if(NT_SUCCESS(pNtQueryVirtualMemory(process_handle, addr, 0, mbi,
            sizeof(MEMORY_BASIC_INFORMATION), &return_length)) != FALSE &&
            return_length == sizeof(MEMORY_BASIC_INFORMATION)) {
        return 1;
    }
    return 0;
}

int virtual_query(void *addr, MEMORY_BASIC_INFORMATION *mbi)
{
    return virtual_query_ex(g_current_process, addr, mbi);
}

void *virtual_alloc_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t allocation_type, uint32_t protection)
{
    SIZE_T real_size = size;
    if(NT_SUCCESS(pNtAllocateVirtualMemory(process_handle, &addr, 0,
            &real_size, allocation_type, protection)) != FALSE) {
        return addr;
    }
    return NULL;
}

void *virtual_alloc(void *addr, uintptr_t size,
    uint32_t allocation_type, uint32_t protection)
{
    return virtual_alloc_ex(g_current_process, addr, size,
        allocation_type, protection);
}

int virtual_protect_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t protection)
{
    DWORD real_size = size; unsigned long old_protect;
    if(NT_SUCCESS(pNtProtectVirtualMemory(process_handle, &addr, &real_size,
            protection, &old_protect)) != FALSE) {
        return 1;
    }
    return 0;
}

int virtual_protect(void *addr, uintptr_t size, uint32_t protection)
{
    return virtual_protect_ex(g_current_process, addr, size, protection);
}

uint32_t get_last_error()
{
    return pRtlGetLastWin32Error();
}

void set_last_error(uint32_t error_value)
{
    pRtlSetLastWin32Error(error_value);
}
