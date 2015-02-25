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
#include "hooking.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"

#define assert(expression, message, return_value) \
    if((expression) == 0) { \
        MessageBox(NULL, message, "Error", 0); \
        return return_value; \
    }

static HANDLE g_current_process;
static uintptr_t g_current_process_id;
static HANDLE g_current_thread;

static int32_t g_win32_error_offset;
static int32_t g_nt_status_offset;

static NTSTATUS (WINAPI *pNtQueryVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID *BaseAddress, ULONG MemoryInformationClass,
    VOID *MemoryInformation, SIZE_T MemoryInformationLength,
    SIZE_T *ReturnLength);

static NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle,
    VOID **BaseAddress, ULONG_PTR ZeroBits, SIZE_T *RegionSize,
    ULONG AllocationType, ULONG Protect);

static NTSTATUS (WINAPI *pNtFreeVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID **BaseAddress, SIZE_T *RegionSize, ULONG FreeType);

static NTSTATUS (WINAPI *pNtProtectVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID **BaseAddress, ULONG *NumberOfBytesToProtect,
    ULONG NewAccessProtection, ULONG *OldAccessProtection);

static NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle,
    ULONG ProcessInformationClass, VOID *ProcessInformation,
    ULONG ProcessInformationLength, ULONG *ReturnLength);

static NTSTATUS (WINAPI *pNtQueryInformationThread)(HANDLE ThreadHandle,
    ULONG ThreadInformationClass, VOID *ThreadInformation,
    ULONG ThreadInformationLength, ULONG *ReturnLength);

static NTSTATUS (WINAPI *pNtQueryObject)(HANDLE Handle,
    ULONG ObjectInformationClass, VOID *ObjectInformation,
    ULONG ObjectInformationLength, ULONG *ReturnLength);

static NTSTATUS (WINAPI *pNtQueryKey)(HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
    ULONG Length, PULONG ResultLength);

static NTSTATUS (WINAPI *pNtDuplicateObject)(HANDLE SourceProcessHandle,
    HANDLE SourceHandle, HANDLE TargetProcessHandle, HANDLE *TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

static NTSTATUS (WINAPI *pNtClose)(HANDLE Handle);

static const char *g_funcnames[] = {
    "NtQueryVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtFreeVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueryInformationProcess",
    "NtQueryInformationThread",
    "NtQueryObject",
    "NtQueryKey",
    "NtDuplicateObject",
    "NtClose",
    NULL,
};

static void **g_pointers[] = {
    (void **) &pNtQueryVirtualMemory,
    (void **) &pNtAllocateVirtualMemory,
    (void **) &pNtFreeVirtualMemory,
    (void **) &pNtProtectVirtualMemory,
    (void **) &pNtQueryInformationProcess,
    (void **) &pNtQueryInformationThread,
    (void **) &pNtQueryObject,
    (void **) &pNtQueryKey,
    (void **) &pNtDuplicateObject,
    (void **) &pNtClose,
};

// Extract the immediate offset from the first "mov eax, dword [eax+imm]" or
// "mov eax, dword [rax+imm]" instruction that occurs.
static int32_t _native_fetch_mov_eax_imm_offset(const uint8_t *func)
{
    for (uint32_t idx = 0; idx < 32; idx++) {
        if(memcmp(func, "\x8b\x80", 2) == 0) {
            return *(uint32_t *)(func + 2);
        }
        if(memcmp(func, "\x8b\x40", 2) == 0) {
            return func[2];
        }
        func += lde(func);
    }
    return -1;
}

static void _native_copy_function(uint8_t *dst, const uint8_t *src)
{
    int len = 0;
    do {
        src += len, dst += len;

        len = lde(src);
        memcpy(dst, src, len);

#if !__x86_64__
        if(*dst == 0xe8) {
            *(uint32_t *)(dst + 1) += src - dst;
        }
#endif
    } while (*src != 0xc2 && *src != 0xc3);
}

int native_init()
{
    g_current_process = GetCurrentProcess();
    g_current_process_id = GetCurrentProcessId();
    g_current_thread = GetCurrentThread();

    uint8_t *memory = VirtualAlloc(NULL, 0x1000,
        MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(memory == NULL) return -1;

    for (uint32_t idx = 0; g_funcnames[idx] != NULL; idx++) {
        *g_pointers[idx] = memory;
        memory += 64;

        const uint8_t *fp = (const uint8_t *) GetProcAddress(
            GetModuleHandle("ntdll"), g_funcnames[idx]);
        if(fp == NULL) {
            pipe("CRITICAL:Error retrieving address of %z!",
                g_funcnames[idx]);
            continue;
        }

        dpipe("INFO:Native function %z (0x%x) -> 0x%x",
            g_funcnames[idx], fp, *g_pointers[idx]);

        _native_copy_function(*g_pointers[idx], fp);
    }

    unsigned long old_protect;
    VirtualProtect(*g_pointers[0], 0x1000, PAGE_EXECUTE_READ, &old_protect);

    FARPROC pRtlGetLastWin32Error = GetProcAddress(
        GetModuleHandle("ntdll"), "RtlGetLastWin32Error");

    FARPROC pRtlGetLastNtStatus = GetProcAddress(
        GetModuleHandle("ntdll"), "RtlGetLastNtStatus");

    g_win32_error_offset = _native_fetch_mov_eax_imm_offset(
        (const uint8_t *) pRtlGetLastWin32Error);
    if(g_win32_error_offset < 0) {
        pipe("CRITICAL:Unknown offset for Win32 Error!");
        return -1;
    }

    dpipe("INFO:Win32Error offset: 0x%x", g_win32_error_offset);

    g_nt_status_offset = _native_fetch_mov_eax_imm_offset(
        (const uint8_t *) pRtlGetLastNtStatus);
    if(g_nt_status_offset < 0) {
        pipe("CRITICAL:Unknown offset for NtStatus!");
        return -1;
    }

    dpipe("INFO:NtStatus   offset: 0x%x", g_nt_status_offset);
    return 0;
}

int virtual_query_ex(HANDLE process_handle, const void *addr,
    MEMORY_BASIC_INFORMATION_CROSS *mbi)
{
    assert(pNtQueryVirtualMemory != NULL,
        "pNtQueryVirtualMemory is NULL!", 0);
    SIZE_T return_length;
    if(NT_SUCCESS(pNtQueryVirtualMemory(process_handle, addr, 0, mbi,
            sizeof(MEMORY_BASIC_INFORMATION_CROSS),
            &return_length)) != FALSE &&
            return_length == sizeof(MEMORY_BASIC_INFORMATION_CROSS)) {
        return 1;
    }
    return 0;
}

int virtual_query(const void *addr, MEMORY_BASIC_INFORMATION_CROSS *mbi)
{
    return virtual_query_ex(get_current_process(), addr, mbi);
}

void *virtual_alloc_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t allocation_type, uint32_t protection)
{
    assert(pNtAllocateVirtualMemory != NULL,
        "pNtAllocateVirtualMemory is NULL!", NULL);
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
    return virtual_alloc_ex(get_current_process(), addr, size,
        allocation_type, protection);
}

int virtual_free_ex(HANDLE process_handle, const void *addr, uintptr_t size,
    uint32_t free_type)
{
    assert(pNtFreeVirtualMemory != NULL, "pNtFreeVirtualMemory is NULL!", 0);
    SIZE_T real_size = size;
    if(NT_SUCCESS(pNtFreeVirtualMemory(process_handle, &addr,
            &real_size, free_type)) != FALSE) {
        return 1;
    }
    return 0;
}

int virtual_free(const void *addr, uintptr_t size, uint32_t free_type)
{
    return virtual_free_ex(get_current_process(), addr, size, free_type);
}

int virtual_protect_ex(HANDLE process_handle, const void *addr,
    uintptr_t size, uint32_t protection)
{
    assert(pNtProtectVirtualMemory != NULL,
        "pNtQueryVirtualMemory is NULL!", 0);
    DWORD real_size = size; unsigned long old_protect;
    if(NT_SUCCESS(pNtProtectVirtualMemory(process_handle, &addr, &real_size,
            protection, &old_protect)) != FALSE) {
        return 1;
    }
    return 0;
}

int virtual_protect(const void *addr, uintptr_t size, uint32_t protection)
{
    return virtual_protect_ex(get_current_process(), addr, size, protection);
}

uint32_t query_information_process(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length)
{
    assert(pNtQueryInformationProcess != NULL,
        "pNtQueryInformationProcess is NULL!", 0);
    ULONG return_length;
    if(NT_SUCCESS(pNtQueryInformationProcess(process_handle,
            information_class, buf, length, &return_length)) != FALSE) {
        return return_length;
    }
    return 0;
}

uint32_t query_information_thread(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length)
{
    assert(pNtQueryInformationThread != NULL,
        "pNtQueryInformationThread is NULL!", 0);
    ULONG return_length;
    if(NT_SUCCESS(pNtQueryInformationThread(process_handle,
            information_class, buf, length, &return_length)) != FALSE) {
        return return_length;
    }
    return 0;
}

uint32_t query_object(HANDLE handle, uint32_t information_class,
    void *buf, uint32_t length)
{
    assert(pNtQueryObject != NULL, "pNtQueryObject is NULL!", 0);
    ULONG return_length;
    if(NT_SUCCESS(pNtQueryObject(handle, information_class,
            buf, length, &return_length)) != FALSE) {
        return return_length;
    }
    return 0;
}

uint32_t query_key(HANDLE key_handle, uint32_t information_class,
    void *buf, uint32_t length)
{
    assert(pNtQueryKey != NULL, "pNtQueryKey is NULL!", 0);
    ULONG return_length;
    if(NT_SUCCESS(pNtQueryKey(key_handle, information_class,
            buf, length, &return_length)) != FALSE) {
        return return_length;
    }
    return 0;
}

int duplicate_handle(HANDLE source_process_handle, HANDLE source_handle,
    HANDLE target_process_handle, HANDLE *target_handle,
    uint32_t desired_access, int inherit_handle, uint32_t options)
{
    assert(pNtDuplicateObject != NULL, "pNtDuplicateObject is NULL!", 0);
    uint32_t handle_attributes = inherit_handle == FALSE ? 0 : 2;
    if(NT_SUCCESS(pNtDuplicateObject(source_process_handle, source_handle,
            target_process_handle, target_handle, desired_access,
            handle_attributes, options)) != FALSE) {
        return 1;
    }
    return 0;
}

int close_handle(HANDLE object_handle)
{
    assert(pNtClose != NULL, "pNtClose is NULL!", 0);
    if(NT_SUCCESS(pNtClose(object_handle)) != FALSE) {
        return 1;
    }
    return 0;
}

void get_last_error(last_error_t *error)
{
    assert(g_win32_error_offset != 0, "Win32 error offset is 0!", );
    assert(g_nt_status_offset != 0, "NT Status offset is 0!", );
    error->lasterror = *(uint32_t *)(readtls(TLS_TEB) + g_win32_error_offset);
    error->nt_status = *(uint32_t *)(readtls(TLS_TEB) + g_nt_status_offset);
}

void set_last_error(last_error_t *error)
{
    assert(g_win32_error_offset != 0, "Win32 error offset is 0!", );
    assert(g_nt_status_offset != 0, "NT Status offset is 0!", );
    *(uint32_t *)(readtls(TLS_TEB) + g_win32_error_offset) = error->lasterror;
    *(uint32_t *)(readtls(TLS_TEB) + g_nt_status_offset) = error->nt_status;
}

HANDLE get_current_process()
{
    assert(g_current_process != NULL,
        "Current process handle is NULL!", NULL);
    return g_current_process;
}

uintptr_t get_current_process_id()
{
    assert(g_current_process_id != 0, "Current process identifier is 0!", 0);
    return g_current_process_id;
}

HANDLE get_current_thread()
{
    assert(g_current_thread != NULL, "Current thread handle is NULL!", NULL);
    return g_current_thread;
}

uintptr_t get_current_thread_id()
{
    assert(g_current_thread != NULL, "Current thread handle is NULL!", 0);
    return tid_from_thread_handle(g_current_thread);
}
