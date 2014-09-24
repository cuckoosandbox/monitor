/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2014 Cuckoo Foundation.

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

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <shlwapi.h>
#include "bson/bson.h"
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"
#include "symbol.h"

static char g_shutdown_mutex[MAX_PATH];

#define HKCU_PREFIX L"\\REGISTRY\\USER\\S-1-5-"
#define HKLM_PREFIX L"\\REGISTRY\\MACHINE"

static LONG (WINAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static LONG (WINAPI *pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static NTSTATUS (WINAPI *pNtQueryAttributesFile)(
    const OBJECT_ATTRIBUTES *ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
);

static NTSTATUS (WINAPI *pNtQueryVolumeInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass
);

static NTSTATUS (WINAPI *pNtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

static NTSTATUS (WINAPI *pNtQueryKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

static PVOID (WINAPI *pRtlAddVectoredExceptionHandler)(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);

void misc_init(const char *shutdown_mutex)
{
    HMODULE mod = GetModuleHandle("ntdll");

    *(FARPROC *) &pNtQueryInformationProcess =
        GetProcAddress(mod, "NtQueryInformationProcess");

    *(FARPROC *) &pNtQueryInformationThread =
        GetProcAddress(mod, "NtQueryInformationThread");

    *(FARPROC *) &pNtQueryAttributesFile =
        GetProcAddress(mod, "NtQueryAttributesFile");

    *(FARPROC *) &pNtQueryVolumeInformationFile =
        GetProcAddress(mod, "NtQueryVolumeInformationFile");

    *(FARPROC *) &pNtQueryInformationFile =
        GetProcAddress(mod, "NtQueryInformationFile");

    *(FARPROC *) &pNtQueryKey =
        GetProcAddress(mod, "NtQueryKey");

    *(FARPROC *) &pRtlAddVectoredExceptionHandler =
        GetProcAddress(mod, "RtlAddVectoredExceptionHandler");

    strncpy(g_shutdown_mutex, shutdown_mutex, sizeof(g_shutdown_mutex));
}

uintptr_t pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi; ULONG size;

    if(NT_SUCCESS(pNtQueryInformationProcess(process_handle,
            ProcessBasicInformation, &pbi, sizeof(pbi), &size)) != FALSE &&
            size == sizeof(pbi)) {
        return pbi.UniqueProcessId;
    }
    return 0;
}

uintptr_t pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; ULONG size;

    if(NT_SUCCESS(pNtQueryInformationThread(thread_handle,
            ThreadBasicInformation, &tbi, sizeof(tbi), &size)) != FALSE &&
            size == sizeof(tbi)) {
        return (uintptr_t) tbi.ClientId.UniqueProcess;
    }
    return 0;
}

uintptr_t parent_process_id()
{
    return pid_from_process_handle(GetCurrentProcess());
}

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj)
{
    FILE_BASIC_INFORMATION info;

    if(NT_SUCCESS(pNtQueryAttributesFile(obj, &info)) != FALSE) {
        return info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? TRUE : FALSE;
    }

    return FALSE;
}

// Hide our module from PEB.
// http://www.openrce.org/blog/view/844/How_to_hide_dll

#define CUT_LIST(item) \
    item.Blink->Flink = item.Flink; \
    item.Flink->Blink = item.Blink

void hide_module_from_peb(HMODULE module_handle)
{
    LDR_MODULE *mod; PEB *peb;

#if __x86_64__
    peb = (PEB *) readtls(0x60);
#else
    peb = (PEB *) readtls(0x30);
#endif

    for (mod = (LDR_MODULE *) peb->LoaderData->InLoadOrderModuleList.Flink;
         mod->BaseAddress != NULL;
         mod = (LDR_MODULE *) mod->InLoadOrderModuleList.Flink) {

        if(mod->BaseAddress == module_handle) {
            CUT_LIST(mod->InLoadOrderModuleList);
            CUT_LIST(mod->InInitializationOrderModuleList);
            CUT_LIST(mod->InMemoryOrderModuleList);
            CUT_LIST(mod->HashTableEntry);

            memset(mod, 0, sizeof(LDR_MODULE));
            break;
        }
    }
}

void destroy_pe_header(HANDLE module_handle)
{
    DWORD old_protect;

    if(VirtualProtect(module_handle, 0x1000,
            PAGE_EXECUTE_READWRITE, &old_protect) != FALSE) {
        memset(module_handle, 0, 512);
        VirtualProtect(module_handle, 0x1000, old_protect, &old_protect);
    }
}

void wcsncpyA(wchar_t *str, const char *value, uint32_t length)
{
    while (*value != 0 && length != 0) {
        *str++ = *value++, length--;
    }
    *str = 0;
}

uint32_t path_from_handle(HANDLE handle, wchar_t *path)
{
    IO_STATUS_BLOCK status; FILE_FS_VOLUME_INFORMATION volume_information;

    // Get the volume serial number of the directory handle.
    if(NT_SUCCESS(pNtQueryVolumeInformationFile(handle, &status,
            &volume_information, sizeof(volume_information),
            FileFsVolumeInformation)) == FALSE) {
        *path = 0;
        return 0;
    }

    FILE_NAME_INFORMATION *name_information = (FILE_NAME_INFORMATION *)
        calloc(1, FILE_NAME_INFORMATION_REQUIRED_SIZE);
    if(name_information == NULL) return 0;

    unsigned long serial_number;

    // Enumerate all harddisks in order to find the
    // corresponding serial number.
    wcscpy(path, L"?:\\");
    for (path[0] = 'A'; path[0] <= 'Z'; path[0]++) {
        if(GetVolumeInformationW(path, NULL, 0, &serial_number, NULL,
                NULL, NULL, 0) == FALSE ||
                serial_number != volume_information.VolumeSerialNumber) {
            continue;
        }

        // Obtain the relative path for this filename on the given harddisk.
        if(NT_SUCCESS(pNtQueryInformationFile(handle, &status,
                name_information, FILE_NAME_INFORMATION_REQUIRED_SIZE,
                FileNameInformation)) == FALSE) {
            continue;
        }

        uint32_t length = name_information->FileNameLength / sizeof(wchar_t);

        // NtQueryInformationFile returns the filepath. Either relative
        // (without backslash) or full path (with backslash.)
        memcpy(path + 2, name_information->FileName,
            name_information->FileNameLength);

        path[2 + length] = 0;

        free(name_information);
        return length + 2;
    }
    free(name_information);
    return 0;
}

static uint32_t _path_handle_long_paths(wchar_t *path)
{
    uint32_t length = lstrlenW(path);

    // Remove the leading "\\??\\".
    if(wcsncmp(path, L"\\??\\", 4) == 0) {
        length -= 4;
        memmove(path, path + 4, length * sizeof(wchar_t));
        path[length] = 0;
    }

    return length;
}

uint32_t path_from_object_attributes(
    const OBJECT_ATTRIBUTES *obj, wchar_t *path)
{
    if(obj == NULL || obj->ObjectName == NULL ||
            obj->ObjectName->Buffer == NULL) {
        return 0;
    }

    if(obj->RootDirectory == NULL) {
        uint32_t length = MIN(
            obj->ObjectName->Length / sizeof(wchar_t),
            MAX_PATH_W
        );

        memcpy(path, obj->ObjectName->Buffer, length * sizeof(wchar_t));
        path[length] = 0;
        return _path_handle_long_paths(path);
    }

    uint32_t offset = path_from_handle(obj->RootDirectory, path);
    path[offset++] = '\\';

    uint32_t length = MIN(
        obj->ObjectName->Length / sizeof(wchar_t),
        MAX_PATH_W - offset
    );

    memcpy(&path[offset], obj->ObjectName->Buffer, length * sizeof(wchar_t));
    path[offset + length] = 0;
    return _path_handle_long_paths(path);
}

static uint32_t _reg_root_handle(HANDLE key_handle, wchar_t *regkey)
{
    const wchar_t *key = NULL;
    switch ((uintptr_t) key_handle) {
    case 0x80000000:
        key = L"HKEY_CLASSES_ROOT";
        break;

    case 0x80000001:
        key = L"HKEY_CURRENT_USER";
        break;

    case 0x80000002:
        key = L"HKEY_LOCAL_MACHINE";
        break;

    case 0x80000003:
        key = L"HKEY_USERS";
        break;

    case 0x80000004:
        key = L"HKEY_PERFORMANCE_DATA";
        break;

    case 0x80000005:
        key = L"HKEY_CURRENT_CONFIG";
        break;

    case 0x80000006:
        key = L"HKEY_DYN_DATA";
        break;
    }

    if(key != NULL) {
        uint32_t length = lstrlenW(key);
        memmove(regkey, key, length * sizeof(wchar_t));
        regkey[length] = 0;
        return length;
    }
    return 0;
}

uint32_t reg_get_key(HANDLE key_handle, wchar_t *regkey)
{
    ULONG ret;

    uint32_t buffer_length =
        sizeof(KEY_NAME_INFORMATION) + MAX_PATH_W * sizeof(wchar_t);

    uint32_t offset = _reg_root_handle(key_handle, regkey);
    if(offset != 0) return offset;

    KEY_NAME_INFORMATION *key_name_information =
        (KEY_NAME_INFORMATION *) calloc(1, buffer_length);
    if(key_name_information == NULL) return 0;

    if(NT_SUCCESS(pNtQueryKey(key_handle, KeyNameInformation,
            key_name_information, buffer_length, &ret)) != FALSE) {

        if(key_name_information->NameLength > MAX_PATH_W * sizeof(wchar_t)) {
            pipe("CRITICAL:Registry key too long?! regkey length: %d",
                key_name_information->NameLength / sizeof(wchar_t));
            free(key_name_information);
            return 0;
        }

        uint32_t length = key_name_information->NameLength / sizeof(wchar_t);
        key_name_information->Name[length] = 0;

        // HKEY_CURRENT_USER is expanded into this ugly
        // \\REGISTRY\\USER\\S-1-5-<bunch of numbers> thing which is not
        // relevant to the monitor and thus we normalize it.
        if(wcsnicmp(key_name_information->Name,
                HKCU_PREFIX, lstrlenW(HKCU_PREFIX)) == 0) {
            offset = _reg_root_handle(HKEY_CURRENT_USER, regkey);
            const wchar_t *subkey = wcschr(
                key_name_information->Name + lstrlenW(HKCU_PREFIX),
                '\\'
            );

            // Subtract the part of the key from the length that
            // we're skipping.
            length -= subkey - key_name_information->Name;

            // Shouldn't be a null pointer but let's just make sure.
            if(subkey != NULL && length != 0) {
                memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
                regkey[offset + length] = 0;
            }

            free(key_name_information);
            return offset + length;
        }

        // HKEY_LOCAL_MACHINE might be expanded into \\REGISTRY\\MACHINE - we
        // normalize this as well.
        if(wcsnicmp(key_name_information->Name,
                HKLM_PREFIX, lstrlenW(HKLM_PREFIX)) == 0) {
            offset = _reg_root_handle(HKEY_LOCAL_MACHINE, regkey);
            const wchar_t *ptr =
                &key_name_information->Name[lstrlenW(HKLM_PREFIX)];

            // Subtract the part of the key from the length that
            // we're skipping.
            length -= lstrlenW(HKLM_PREFIX);

            memmove(&regkey[offset], ptr, length * sizeof(wchar_t));
            regkey[offset + length] = 0;

            free(key_name_information);
            return lstrlenW(regkey);
        }

        memmove(regkey, key_name_information->Name, length * sizeof(wchar_t));
        regkey[length] = 0;

        free(key_name_information);
        return length;
    }
    return 0;
}

uint32_t reg_get_key_ascii(HANDLE key_handle,
    const char *subkey, uint32_t length, wchar_t *regkey)
{
    uint32_t offset = reg_get_key(key_handle, regkey);

    if(subkey == NULL || length == 0) {
        subkey = "(Default)";
        length = strlen(subkey);
    }

    length = MIN(length, MAX_PATH_W - offset);

    regkey[offset++] = '\\';
    wcsncpyA(regkey, subkey, length);
    regkey[offset + length] = 0;
    return offset + length;
}

uint32_t reg_get_key_asciiz(HANDLE key_handle,
    const char *subkey, wchar_t *regkey)
{
    return reg_get_key_ascii(key_handle, subkey,
        subkey != NULL ? strlen(subkey) : 0, regkey);
}

uint32_t reg_get_key_uni(HANDLE key_handle,
    const wchar_t *subkey, uint32_t length, wchar_t *regkey)
{
    uint32_t offset = reg_get_key(key_handle, regkey);

    if(subkey == NULL || length == 0) {
        subkey = L"(Default)";
        length = lstrlenW(subkey);
    }

    length = MIN(length, MAX_PATH_W - offset);

    regkey[offset++] = '\\';
    memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
    regkey[offset + length] = 0;
    return offset + length;
}

uint32_t reg_get_key_uniz(HANDLE key_handle,
    const wchar_t *subkey, wchar_t *regkey)
{
    return reg_get_key_uni(key_handle, subkey,
        subkey != NULL ? lstrlenW(subkey) : 0, regkey);
}

uint32_t reg_get_key_unistr(HANDLE key_handle,
    const UNICODE_STRING *unistr, wchar_t *regkey)
{
    const wchar_t *ptr = NULL; uint32_t length = 0;

    if(unistr != NULL && unistr->Buffer != NULL && unistr->Length != 0) {
        ptr = unistr->Buffer;
        length = unistr->Length / sizeof(wchar_t);
    }

    return reg_get_key_uni(key_handle, ptr, length, regkey);
}

uint32_t reg_get_key_objattr(const OBJECT_ATTRIBUTES *obj, wchar_t *regkey)
{
    if(obj != NULL) {
        return reg_get_key_unistr(obj->RootDirectory,
            obj->ObjectName, regkey);
    }
    return 0;
}

void get_ip_port(const struct sockaddr *addr, const char **ip, int *port)
{
    if(addr == NULL) return;

    // TODO IPv6 support.
    if(addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
        *ip = inet_ntoa(addr4->sin_addr);
        *port = htons(addr4->sin_port);
    }
}

int is_shutting_down()
{
    HANDLE mutex_handle = OpenMutex(SYNCHRONIZE, FALSE, g_shutdown_mutex);
    if(mutex_handle != NULL) {
        CloseHandle(mutex_handle);
        return 1;
    }
    return 0;
}

void library_from_unicode_string(const UNICODE_STRING *us,
    char *library, int32_t length)
{
    memset(library, 0, length);

    if(us != NULL && us->Buffer != NULL) {
        const wchar_t *libname = us->Buffer;

        // Follow through all directories.
        for (const wchar_t *ptr = libname; *ptr != 0; ptr++) {
            if(*ptr == '\\' || *ptr == '/') {
                libname = ptr + 1;
            }
        }

        // Copy the library name into our ascii library buffer.
        length = MIN(length - 1, lstrlenW(libname));
        for (int32_t idx = 0; idx < length; idx++) {
            library[idx] = (char) libname[idx];
        }

        // Strip off any remaining ".dll".
        for (char *ptr = library; *ptr != 0; ptr++) {
            if(stricmp(ptr, ".dll") == 0) {
                *ptr = 0;
                break;
            }
        }
    }
}

#if !__x86_64__

int stacktrace(uint32_t ebp, uint32_t *addrs, uint32_t length)
{
    uint32_t top = readtls(0x04);
    uint32_t bottom = readtls(0x08);

    int count = 0;
    for (; ebp >= bottom && ebp < top && length != 0; count++, length--) {
        addrs[count] = *(uint32_t *)(ebp + 4);
        ebp = *(uint32_t *) ebp;

        // No need to track any further.
        if(addrs[count] == 0) {
            break;
        }
    }

    // Check whether any of the return addresses are "spoofed", that is, they
    // belong to one of our hooks. If so, then we fetch the original return
    // address from the return address list and use that to provide a symbol.
    // As the list traverses as last in first out we start at the "end" of the
    // return address list (the oldest return address in it really) and
    // iterate upwards from there on.
    for (uint32_t idx = count, listidx = 0; idx != 0; idx--) {
        if(hook_is_spoofed_return_address(addrs[idx - 1]) != 0) {
            addrs[idx - 1] = hook_retaddr_get(listidx++);
        }
    }

    return count;
}

#endif

static LONG CALLBACK _exception_handler(
    EXCEPTION_POINTERS *exception_pointers)
{
    char buf[128]; CONTEXT *ctx = exception_pointers->ContextRecord;
    bson b, s, e;

    hook_disable();

    bson_init(&b);
    bson_init(&s);
    bson_init(&e);

#if __x86_64__
    static const char *regnames[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        NULL,
    };

    uintptr_t regvalues[] = {
        ctx->Rax, ctx->Rcx, ctx->Rdx, ctx->Rbx,
        ctx->Rsp, ctx->Rbp, ctx->Rsi, ctx->Rdi,
        ctx->R8,  ctx->R9,  ctx->R10, ctx->R11,
        ctx->R12, ctx->R13, ctx->R14, ctx->R15,
    };
#else
    static const char *regnames[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        NULL,
    };

    uintptr_t regvalues[] = {
        ctx->Eax, ctx->Ecx, ctx->Edx, ctx->Ebx,
        ctx->Esp, ctx->Ebp, ctx->Esi, ctx->Edi,
    };
#endif

    for (uint32_t idx = 0; regnames[idx] != NULL; idx++) {
        bson_append_long(&b, regnames[idx], regvalues[idx]);
    }

    uintptr_t return_addresses[32]; uint32_t count = 0;

    memset(return_addresses, 0, sizeof(return_addresses));

#if !__x86_64__
    count = stacktrace(exception_pointers->ContextRecord->Ebp,
        return_addresses, sizeof(return_addresses) / sizeof(uint32_t));
#endif

    char sym[512], argidx[12];

    const uint8_t *exception_address = (const uint8_t *)
        exception_pointers->ExceptionRecord->ExceptionAddress;

    sprintf(buf, "0x%p", exception_address);
    bson_append_string(&e, "address", buf);

#if DEBUG
    char insn[DISASM_BUFSIZ];
    if(disasm(exception_address, insn) == 0) {
        bson_append_string(&e, "instruction", insn);
    }
#endif

#if __x86_64__
    sym[0] = 0;
#else
    symbol(exception_address, sym, sizeof(sym));
#endif
    bson_append_string(&e, "symbol", sym);

    sprintf(buf, "0x%08x", (uint32_t)
        exception_pointers->ExceptionRecord->ExceptionCode);
    bson_append_string(&e, "exception_code", buf);

    for (uint32_t idx = 0; idx < count; idx++) {
        if(return_addresses[idx] == 0) break;

#if __x86_64__
        sym[0] = 0;
#else
        symbol((const uint8_t *) return_addresses[idx], sym, sizeof(sym));
#endif

        sprintf(argidx, "%d", idx);
        bson_append_start_array(&s, argidx);

        sprintf(argidx, "0x%p", (void *) return_addresses[idx]);
        bson_append_string(&s, "0", argidx);

        bson_append_string(&s, "1", sym);
        bson_append_finish_array(&s);
    }

    bson_finish(&e);
    bson_finish(&s);
    bson_finish(&b);

    log_api(3, 1, 0, "zzz", &e, &b, &s);

    bson_destroy(&e);
    bson_destroy(&s);
    bson_destroy(&b);

    hook_enable();

    return EXCEPTION_CONTINUE_SEARCH;
}

void setup_exception_handler()
{
    pRtlAddVectoredExceptionHandler(TRUE, &_exception_handler);
}
