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
        message_box(NULL, message, "Error", 0); \
        return return_value; \
    }

static HANDLE g_current_process;
static uint32_t g_current_process_id;
static HANDLE g_current_thread;
static HANDLE g_stdin_handle;
static HANDLE g_stdout_handle;
static HANDLE g_stderr_handle;

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
    CONST VOID **BaseAddress, SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection, ULONG *OldAccessProtection);

static NTSTATUS (WINAPI *pNtReadVirtualMemory)(HANDLE ProcessHandle,
    PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded);

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

static NTSTATUS (WINAPI *pNtWriteFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, const void *Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);

static NTSTATUS (WINAPI *pNtFsControlFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    const void *InputBuffer, ULONG InputBufferLength,
    void *OutputBuffer, ULONG OutputBufferLength);

static NTSTATUS (WINAPI *pNtSetInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

static NTSTATUS (WINAPI *pNtClose)(HANDLE Handle);

static NTSTATUS (WINAPI *pNtDelayExecution)(BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

static NTSTATUS (WINAPI *pNtWaitForSingleObject)(HANDLE Object,
    BOOLEAN Alertable, PLARGE_INTEGER Timeout);

static NTSTATUS (WINAPI *pNtOpenThread)(PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

static NTSTATUS (WINAPI *pNtResumeThread)(
    HANDLE ThreadHandle, PULONG SuspendCount);

static DWORD (WINAPI *pGetTickCount)();

static NTSTATUS (WINAPI *pLdrRegisterDllNotification)(ULONG Flags,
    LDR_DLL_NOTIFICATION_FUNCTION LdrDllNotificationFunction,
    VOID *Context, VOID **Cookie);

static DWORD (WINAPI *pGetWindowThreadProcessId)(
    HWND hWnd, DWORD *lpdwProcessId);

static int (WINAPI *pMessageBoxA)(
    HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

static const char *g_funcnames[] = {
    "NtQueryVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtFreeVirtualMemory",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtQueryInformationProcess",
    "NtQueryInformationThread",
    "NtQueryObject",
    "NtQueryKey",
    "NtDuplicateObject",
    "NtWriteFile",
    "NtFsControlFile",
    "NtSetInformationFile",
    "NtClose",
    "NtDelayExecution",
    "NtWaitForSingleObject",
    "NtOpenThread",
    "NtResumeThread",
    NULL,
};

static void **g_pointers[] = {
    (void **) &pNtQueryVirtualMemory,
    (void **) &pNtAllocateVirtualMemory,
    (void **) &pNtFreeVirtualMemory,
    (void **) &pNtProtectVirtualMemory,
    (void **) &pNtReadVirtualMemory,
    (void **) &pNtQueryInformationProcess,
    (void **) &pNtQueryInformationThread,
    (void **) &pNtQueryObject,
    (void **) &pNtQueryKey,
    (void **) &pNtDuplicateObject,
    (void **) &pNtWriteFile,
    (void **) &pNtFsControlFile,
    (void **) &pNtSetInformationFile,
    (void **) &pNtClose,
    (void **) &pNtDelayExecution,
    (void **) &pNtWaitForSingleObject,
    (void **) &pNtOpenThread,
    (void **) &pNtResumeThread,
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
        if(*dst == 0xe8 || *dst == 0xe9) {
            *(uint32_t *)(dst + 1) += src - dst;
        }
#endif
    } while (*src != 0xc2 && *src != 0xc3);
}

static uint8_t *_native_follow_get_tick_count(uint8_t *addr)
{
    // Handles the case under Windows 7 where you have to follow a short jump
    // and an indirect jump before getting to the actual function.
    if(*addr == 0xeb) {
        addr = addr + 2 + *(int8_t *)(addr + 1);

        if(*addr == 0xff && addr[1] == 0x25) {
#if __x86_64__
            addr += *(uint32_t *)(addr + 2) + 6;
#else
            addr = *(uint8_t **)(addr + 2);
#endif
            addr = *(uint8_t **) addr;
        }
    }
    return addr;
}

int native_init()
{
    g_current_process = GetCurrentProcess();
    g_current_process_id = GetCurrentProcessId();
    g_current_thread = GetCurrentThread();
    g_stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
    g_stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    g_stderr_handle = GetStdHandle(STD_ERROR_HANDLE);

    // TODO Use the slab allocator here as well.
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

        _native_copy_function(*g_pointers[idx], fp);
    }

    *(uint8_t **) &pGetTickCount = memory;
    memory += 128;

    // Checked that this will work under at least Windows XP, Windows 7, and
    // 64-bit Windows 7.
    uint8_t *get_tick_count_addr = _native_follow_get_tick_count((uint8_t *)
        GetProcAddress(GetModuleHandle("kernel32"), "GetTickCount"));

    _native_copy_function((uint8_t *) pGetTickCount, get_tick_count_addr);

    unsigned long old_protect;
    VirtualProtect(*g_pointers[0], 0x1000, PAGE_EXECUTE_READ, &old_protect);

    *(FARPROC *) &pLdrRegisterDllNotification = GetProcAddress(
        GetModuleHandle("ntdll"), "LdrRegisterDllNotification");

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

    g_nt_status_offset = _native_fetch_mov_eax_imm_offset(
        (const uint8_t *) pRtlGetLastNtStatus);
    if(g_nt_status_offset < 0) {
        pipe("CRITICAL:Unknown offset for NtStatus!");
        return -1;
    }
    return 0;
}

int virtual_query_ex(HANDLE process_handle, const void *addr,
    MEMORY_BASIC_INFORMATION_CROSS *mbi)
{
    assert(pNtQueryVirtualMemory != NULL,
        "pNtQueryVirtualMemory is NULL!", 0);
    SIZE_T return_length;
    if(NT_SUCCESS(pNtQueryVirtualMemory(process_handle, addr, 0, mbi,
            sizeof(MEMORY_BASIC_INFORMATION_CROSS), &return_length)) != FALSE
            && return_length == sizeof(MEMORY_BASIC_INFORMATION_CROSS)) {
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

void *virtual_alloc_rw(void *addr, uintptr_t size)
{
    return virtual_alloc(addr, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

NTSTATUS virtual_protect_ex(HANDLE process_handle, const void *addr,
    uintptr_t size, uint32_t protection)
{
    assert(pNtProtectVirtualMemory != NULL,
        "pNtQueryVirtualMemory is NULL!", 0);
    SIZE_T real_size = size; ULONG old_protect;
    return pNtProtectVirtualMemory(process_handle, &addr, &real_size,
        protection, &old_protect);
}

NTSTATUS virtual_protect(const void *addr, uintptr_t size,
    uint32_t protection)
{
    return virtual_protect_ex(get_current_process(), addr, size, protection);
}

NTSTATUS virtual_read_ex(HANDLE process_handle, void *addr,
    void *buffer, uintptr_t *size)
{
    assert(pNtReadVirtualMemory != NULL, "pNtReadVirtualMemory is NULL!", 0);
    SIZE_T real_size = *size;
    NTSTATUS ret = pNtReadVirtualMemory(process_handle, addr,
        buffer, real_size, &real_size);
    *size = real_size;
    return ret;
}

NTSTATUS virtual_read(void *addr, void *buffer, uintptr_t *size)
{
    return virtual_read_ex(get_current_process(), addr, buffer, size);
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

NTSTATUS write_file(HANDLE file_handle, const void *buffer, uint32_t length,
    uint32_t *bytes_written)
{
    assert(pNtWriteFile != NULL, "pNtWriteFile is NULL!", 0);
    IO_STATUS_BLOCK status_block;

    NTSTATUS ret = pNtWriteFile(file_handle, NULL, NULL, NULL,
        &status_block, buffer, length, NULL, NULL);

    if(NT_SUCCESS(ret) != FALSE && bytes_written != NULL) {
        *bytes_written = status_block.Information;
    }
    return ret;
}

#define FSCTL_PIPE_TRANSCEIVE \
    CTL_CODE(FILE_DEVICE_NAMED_PIPE, 5, \
    METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

NTSTATUS transact_named_pipe(HANDLE pipe_handle,
    const void *inbuf, uintptr_t inbufsz, void *outbuf, uintptr_t outbufsz,
    uintptr_t *written)
{
    if(pNtFsControlFile == NULL && pNtWaitForSingleObject == NULL) {
        DWORD _written = 0;
        TransactNamedPipe(pipe_handle, (void *) inbuf, inbufsz,
            (void *) outbuf, outbufsz, &_written, NULL);
        if(written != NULL) {
            *written = _written;
        }
        return 0;
    }

    assert(pNtFsControlFile != NULL, "pNtFsControlFile is NULL!", 0);
    assert(pNtWaitForSingleObject != NULL,
        "pNtWaitForSingleObject is NULL!", 0);

    IO_STATUS_BLOCK status_block;

    NTSTATUS ret = pNtFsControlFile(pipe_handle, NULL, NULL, NULL,
        &status_block, FSCTL_PIPE_TRANSCEIVE, inbuf, inbufsz, outbuf,
        outbufsz);
    if(ret == STATUS_PENDING) {
        ret = pNtWaitForSingleObject(pipe_handle, FALSE, NULL);
        if(NT_SUCCESS(ret) != FALSE) {
            ret = status_block._.Status;
        }
    }

    if(NT_SUCCESS(ret) != FALSE && written != NULL) {
        *written = status_block.Information;
    }
    return ret;
}

NTSTATUS set_named_pipe_handle_mode(HANDLE pipe_handle, uint32_t mode)
{
    if(pNtSetInformationFile == NULL) {
        DWORD _mode = mode;
        SetNamedPipeHandleState(pipe_handle, &_mode, NULL, NULL);
        return 0;
    }

    assert(pNtSetInformationFile != NULL,
        "pNtSetInformationFile is NULL!", 0);

    FILE_PIPE_INFORMATION pipe_information; IO_STATUS_BLOCK status_block;

    pipe_information.CompletionMode = (mode & PIPE_NOWAIT) ?
        FILE_PIPE_COMPLETE_OPERATION : FILE_PIPE_QUEUE_OPERATION;

    pipe_information.ReadMode = (mode & PIPE_READMODE_MESSAGE) ?
        FILE_PIPE_MESSAGE_MODE : FILE_PIPE_BYTE_STREAM_MODE;

    return pNtSetInformationFile(pipe_handle, &status_block,
        &pipe_information, sizeof(pipe_information), FilePipeInformation);
}

int close_handle(HANDLE object_handle)
{
    assert(pNtClose != NULL, "pNtClose is NULL!", 0);
    if(NT_SUCCESS(pNtClose(object_handle)) != FALSE) {
        return 1;
    }
    return 0;
}

void sleep(uint32_t milliseconds)
{
    // This should only be the case at the very beginning of execution.
    if(pNtDelayExecution == NULL) {
        Sleep(milliseconds);
        return;
    }

    assert(pNtDelayExecution != NULL, "pNtDelayExecution is NULL!", );
    LARGE_INTEGER li;
    li.QuadPart = -10000 * (uint64_t) milliseconds;

    pNtDelayExecution(FALSE, &li);
}

uint32_t get_tick_count()
{
    return pGetTickCount();
}

void register_dll_notification(LDR_DLL_NOTIFICATION_FUNCTION fn, void *param)
{
    void *cookie = NULL;
    if(pLdrRegisterDllNotification != NULL) {
        pLdrRegisterDllNotification(0, fn, param, &cookie);
    }
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

uint32_t get_current_process_id()
{
    assert(g_current_process_id != 0, "Current process identifier is 0!", 0);
    return g_current_process_id;
}

HANDLE get_current_thread()
{
    assert(g_current_thread != NULL, "Current thread handle is NULL!", NULL);
    return g_current_thread;
}

uint32_t get_current_thread_id()
{
    assert(g_current_thread != NULL, "Current thread handle is NULL!", 0);
    return tid_from_thread_handle(g_current_thread);
}

uint32_t get_window_thread_process_id(HWND hwnd, uint32_t *pid)
{
    if(pGetWindowThreadProcessId == NULL) {
        *(FARPROC *) &pGetWindowThreadProcessId = GetProcAddress(
            LoadLibrary("user32"), "GetWindowThreadProcessId");
    }

    uint32_t tid = 0; DWORD _pid = 0;
    if(pGetWindowThreadProcessId != NULL) {
        tid = pGetWindowThreadProcessId(hwnd, &_pid);
        *pid = _pid;
    }

    return tid;
}

int message_box(HWND hwnd, const char *body, const char *title, int flags)
{
    if(pMessageBoxA == NULL) {
        *(FARPROC *) &pMessageBoxA = GetProcAddress(
            LoadLibrary("user32"), "MessageBoxA");
    }

    if(pMessageBoxA != NULL) {
        return pMessageBoxA(hwnd, body, title, flags);
    }

    return 0;
}

HANDLE open_thread(uint32_t desired_access, uint32_t thread_identifier)
{
    assert(pNtOpenThread != NULL, "pNtOpenThread is NULL!", NULL);

    HANDLE thread_handle; OBJECT_ATTRIBUTES objattr; CLIENT_ID cid;

    InitializeObjectAttributes(&objattr, NULL, 0, NULL, NULL);

    cid.UniqueProcess = NULL;
    cid.UniqueThread = (HANDLE)(uintptr_t) thread_identifier;

    NTSTATUS ret = pNtOpenThread(
        &thread_handle, desired_access, &objattr, &cid
    );

    if(NT_SUCCESS(ret) != FALSE) {
        return thread_handle;
    }
    return NULL;
}

uint32_t resume_thread(HANDLE thread_handle)
{
    assert(pNtResumeThread != NULL, "pNtResumeThread is NULL!", 0);

    DWORD suspend_count = 0;
    NTSTATUS ret = pNtResumeThread(thread_handle, &suspend_count);
    if(NT_SUCCESS(ret) != FALSE) {
        return suspend_count;
    }
    return 0;
}

int set_std_handle(DWORD std_handle, HANDLE file_handle)
{
    if(std_handle == STD_INPUT_HANDLE) {
        g_stdin_handle = file_handle;
        return 0;
    }
    if(std_handle == STD_OUTPUT_HANDLE) {
        g_stdout_handle = file_handle;
        return 0;
    }
    if(std_handle == STD_ERROR_HANDLE) {
        g_stderr_handle = file_handle;
        return 0;
    }
    return -1;
}

int is_std_handle(HANDLE file_handle)
{
    return
        file_handle == g_stdin_handle ||
        file_handle == g_stdout_handle ||
        file_handle == g_stderr_handle;
}
