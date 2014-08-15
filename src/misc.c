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
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"

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

    strncpy(g_shutdown_mutex, shutdown_mutex, sizeof(g_shutdown_mutex));
}

uintptr_t pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi; ULONG size;

    if(NT_SUCCESS(pNtQueryInformationProcess(process_handle,
            ProcessBasicInformation, &pbi, sizeof(pbi), &size)) &&
            size == sizeof(pbi)) {
        return pbi.UniqueProcessId;
    }
    return 0;
}

uintptr_t pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; ULONG size;

    if(NT_SUCCESS(pNtQueryInformationThread(thread_handle,
            ThreadBasicInformation, &tbi, sizeof(tbi), &size)) &&
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

    if(NT_SUCCESS(pNtQueryAttributesFile(obj, &info))) {
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

uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len)
{
    IO_STATUS_BLOCK status; FILE_FS_VOLUME_INFORMATION volume_information;

    unsigned char buf[FILE_NAME_INFORMATION_REQUIRED_SIZE];
    FILE_NAME_INFORMATION *name_information = (FILE_NAME_INFORMATION *) buf;

    // Get the volume serial number of the directory handle.
    if(NT_SUCCESS(pNtQueryVolumeInformationFile(handle, &status,
            &volume_information, sizeof(volume_information),
            FileFsVolumeInformation)) == 0) {
        return 0;
    }

    unsigned long serial_number;

    // Enumerate all harddisks in order to find the
    // corresponding serial number.
    wcscpy(path, L"?:\\");
    for (path[0] = 'A'; path[0] <= 'Z'; path[0]++) {
        if(GetVolumeInformationW(path, NULL, 0, &serial_number, NULL,
                NULL, NULL, 0) == 0 ||
                serial_number != volume_information.VolumeSerialNumber) {
            continue;
        }

        // Obtain the relative path for this filename on the given harddisk.
        if(NT_SUCCESS(pNtQueryInformationFile(handle, &status,
                name_information, FILE_NAME_INFORMATION_REQUIRED_SIZE,
                FileNameInformation)) == 0) {
            continue;
        }

        uint32_t length = name_information->FileNameLength / sizeof(wchar_t);

        // NtQueryInformationFile omits the "C:" part in a filename.
        wcsncpy(path + 2, name_information->FileName, path_buffer_len - 2);

        return length + 2 < path_buffer_len ?
            length + 2 : path_buffer_len - 1;
    }
    return 0;
}

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length)
{
    if(obj == NULL || obj->ObjectName == NULL ||
            obj->ObjectName->Buffer == NULL) {
        return 0;
    }

    uint32_t obj_length = obj->ObjectName->Length / sizeof(wchar_t);

    if(obj->RootDirectory == NULL) {
        wcsncpy(path, obj->ObjectName->Buffer, buffer_length);
        return obj_length > buffer_length ? buffer_length : obj_length;
    }

    uint32_t length =
        path_from_handle(obj->RootDirectory, path, buffer_length);

    path[length++] = L'\\';
    wcsncpy(&path[length], obj->ObjectName->Buffer, buffer_length - length);

    length += obj_length;
    return length > buffer_length ? buffer_length : length;
}

int ensure_absolute_path(wchar_t *out, const wchar_t *in, int length)
{
    if(!wcsncmp(in, L"\\??\\", 4)) {
        length -= 4, in += 4;
        wcsncpy(out, in, length < MAX_PATH ? length : MAX_PATH);
        return length;
    }
    else if(in[1] != ':' || (in[2] != '\\' && in[2] != '/')) {
        wchar_t cur_dir[MAX_PATH], fname[MAX_PATH];
        GetCurrentDirectoryW(ARRAYSIZE(cur_dir), cur_dir);

        // Ensure the filename is zero-terminated.
        wcsncpy(fname, in, length < MAX_PATH ? length : MAX_PATH);
        fname[length] = 0;

        PathCombineW(out, cur_dir, fname);
        return lstrlenW(out);
    }
    else {
        wcsncpy(out, in, length < MAX_PATH ? length : MAX_PATH);
        return length;
    }
}

uint32_t reg_get_key(HANDLE key_handle, wchar_t *regkey, uint32_t length)
{
    ULONG ret; uint8_t buffer[sizeof(ULONG) + MAX_PATH_W * sizeof(wchar_t)];
    KEY_NAME_INFORMATION *key_name_information =
        (KEY_NAME_INFORMATION *) buffer;

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
        length = lstrlenW(key);
        memcpy(regkey, key, length * sizeof(wchar_t));
        regkey[length] = 0;
        return length;
    }

    if(NT_SUCCESS(pNtQueryKey(key_handle, KeyNameInformation,
            key_name_information, sizeof(buffer), &ret))) {

        if(key_name_information->NameLength > length) {
            pipe("CRITICAL:Registry key too long?! regkey length: %d",
                key_name_information->NameLength / sizeof(wchar_t));
            return 0;
        }

        // HKEY_CURRENT_USER is expanded into this ugly
        // \\REGISTRY\\USER\\S-1-5-<bunch of numbers> thing which is not
        // relevant to the monitor and thus we normalize it.
        if(wcsncmp(key_name_information->Name,
                HKCU_PREFIX, lstrlenW(HKCU_PREFIX)) == 0) {
            uint32_t offset = reg_get_key(HKEY_CURRENT_USER, regkey, length);
            const wchar_t *subkey =
                wcschr(regkey + lstrlenW(HKCU_PREFIX), '\\');

            // Shouldn't be a null pointer but let's just make sure.
            if(subkey != NULL) {
                wcsncpy(&regkey[offset], subkey, length - offset);
            }

            return lstrlenW(regkey);
        }

        // HKEY_LOCAL_MACHINE might be expanded into \\REGISTRY\\MACHINE - we
        // normalize this as well.
        if(wcsncmp(key_name_information->Name,
                HKLM_PREFIX, lstrlenW(HKLM_PREFIX)) == 0) {
            uint32_t offset = reg_get_key(HKEY_LOCAL_MACHINE, regkey, length);
            wcsncpy(&regkey[offset],
                &key_name_information->Name[lstrlenW(HKLM_PREFIX)],
                length - offset);
            return lstrlenW(regkey);
        }

        memcpy(regkey, key_name_information->Name,
            key_name_information->NameLength);

        uint32_t length = key_name_information->NameLength / sizeof(wchar_t);

        regkey[length] = 0;
        return length;
    }
    return 0;
}

uint32_t reg_get_key_objattr(const OBJECT_ATTRIBUTES *obj,
    wchar_t *regkey, uint32_t length)
{
    if(obj != NULL) {
        length = reg_get_key(obj->RootDirectory, regkey, MAX_PATH_W);

        // TODO Also use (Default) when Length is zero?
        if(obj->ObjectName != NULL && obj->ObjectName->Length != 0) {
            length = MIN(
                obj->ObjectName->Length / sizeof(wchar_t),
                MAX_PATH_W - length);

            wcsncpy(&regkey[length], obj->ObjectName->Buffer, length);
            return lstrlenW(regkey);
        }
        return length;
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
