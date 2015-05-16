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

#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>
#include "bson/bson.h"
#include "hooking.h"
#include "ignore.h"
#include "log.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"
#include "symbol.h"

static char g_shutdown_mutex[MAX_PATH];
static array_t g_unicode_buffer_ptr_array;
static array_t g_unicode_buffer_use_array;

static uintptr_t g_monitor_start;
static uintptr_t g_monitor_end;

void (*g_hook_library)(const char *library);

#define HKCU_PREFIX  L"\\REGISTRY\\USER\\S-1-5-"
#define HKCU_PREFIX2 L"HKEY_USERS\\S-1-5-"
#define HKLM_PREFIX  L"\\REGISTRY\\MACHINE"

static PVOID (WINAPI *pRtlAddVectoredExceptionHandler)(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);

static LONG CALLBACK _exception_handler(
    EXCEPTION_POINTERS *exception_pointers);

static wchar_t g_aliases[64][2][MAX_PATH];
static uint32_t g_alias_index;

#define ADD_ALIAS(before, after) \
    if(g_alias_index == 64) { \
        pipe("CRITICAL:Too many aliases!"); \
        exit(1); \
    } \
    wcscpy(g_aliases[g_alias_index][0], before); \
    wcscpy(g_aliases[g_alias_index][1], after); \
    g_alias_index++;

void misc_init(HMODULE module_handle, const char *shutdown_mutex)
{
    g_monitor_start = (uintptr_t) module_handle;
    g_monitor_end = g_monitor_start +
        module_image_size((const uint8_t *) module_handle);

    HMODULE mod = GetModuleHandle("ntdll");

    *(FARPROC *) &pRtlAddVectoredExceptionHandler =
        GetProcAddress(mod, "RtlAddVectoredExceptionHandler");

    pRtlAddVectoredExceptionHandler(TRUE, &_exception_handler);

    strncpy(g_shutdown_mutex, shutdown_mutex, sizeof(g_shutdown_mutex));

    array_init(&g_unicode_buffer_ptr_array);
    array_init(&g_unicode_buffer_use_array);

    ADD_ALIAS(L"\\SystemRoot\\", L"C:\\Windows\\");

    wchar_t device_name[4], target_path[MAX_PATH];

    for (wchar_t ch = 'A'; ch <= 'Z'; ch++) {
        device_name[0] = ch, device_name[1] = ':', device_name[2] = 0;
        if(QueryDosDeviceW(device_name, target_path, MAX_PATH) != 0) {
            // Ensure both paths are backslash-terminated to avoid issues
            // between "\\Device\\HarddiskVolume1" and
            // "\\Device\\HarddiskVolume10".
            wcscat(device_name, L"\\");
            wcscat(target_path, L"\\");

            ADD_ALIAS(target_path, device_name);
        }
    }
}

void misc_set_hook_library(void (*monitor_hook)(const char *library))
{
    g_hook_library = monitor_hook;
}

void hook_library(const char *library)
{
    g_hook_library(library);
}

// Maximum number of buffers that we reuse.
#define UNICODE_BUFFER_COUNT (0x1000/sizeof(void *))

wchar_t *get_unicode_buffer()
{
    uint8_t *used = (uint8_t *)
        array_get(&g_unicode_buffer_use_array, get_current_thread_id());

    wchar_t **ptrs = (wchar_t **)
        array_get(&g_unicode_buffer_ptr_array, get_current_thread_id());

    // If not done yet, allocate initial memory management data.
    if(used == NULL && ptrs == NULL) {
        used = (uint8_t *)
            virtual_alloc_rw(NULL, UNICODE_BUFFER_COUNT * sizeof(uint8_t));

        ptrs = (wchar_t **)
            virtual_alloc_rw(NULL, UNICODE_BUFFER_COUNT * sizeof(wchar_t **));

        array_set(&g_unicode_buffer_use_array, get_current_thread_id(), used);
        array_set(&g_unicode_buffer_ptr_array, get_current_thread_id(), ptrs);
    }

    for (uint32_t idx = 0; idx < UNICODE_BUFFER_COUNT; idx++) {
        if(ptrs[idx] == NULL) {
            ptrs[idx] =
                virtual_alloc_rw(NULL, (MAX_PATH_W+1) * sizeof(wchar_t));
            if(ptrs[idx] == NULL) {
                pipe("CRITICAL:Error allocating memory for unicode buffer");
            }
        }

        // Return this pointer if it has not been used yet. Zero-terminate it
        // just in case.
        if(used[idx] == 0) {
            used[idx] = 1, *ptrs[idx] = 0;
            return ptrs[idx];
        }
    }

    // If we get here there is probably a memory leak going on somewhere.
    pipe("CRITICAL:We probably encountered a memory leak with regards to "
        "unicode buffers somewhere");

    // However, just in case, return some memory in order not to crash.
    return virtual_alloc_rw(NULL, (MAX_PATH_W+1) * sizeof(wchar_t));
}

void free_unicode_buffer(wchar_t *ptr)
{
    uint8_t *used = (uint8_t *)
        array_get(&g_unicode_buffer_use_array, get_current_thread_id());

    wchar_t **ptrs = (wchar_t **)
        array_get(&g_unicode_buffer_ptr_array, get_current_thread_id());

    // Cross-reference the pointer against the list of pointers. If found,
    // set used to zero.
    for (uint32_t idx = 0; idx < UNICODE_BUFFER_COUNT; idx++) {
        if(ptrs[idx] == ptr) {
            used[idx] = 0;
            return;
        }
    }

    // If we reach here, then this buffer is not maintained by the list of
    // available buffers, and we have to deallocate it manually.
    virtual_free(ptr, (MAX_PATH_W+1) * sizeof(wchar_t), MEM_RELEASE);
}

uintptr_t pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi; uintptr_t ret = 0;

    if(process_handle == get_current_process()) {
        return get_current_process_id();
    }

    if(duplicate_handle(get_current_process(), process_handle,
            get_current_process(), &process_handle, PROCESS_QUERY_INFORMATION,
            FALSE, 0) == FALSE) {
        return 0;
    }

    uint32_t length = query_information_process(process_handle,
        ProcessBasicInformation, &pbi, sizeof(pbi));
    if(length == sizeof(pbi)) {
        ret = pbi.UniqueProcessId;
    }

    close_handle(process_handle);
    return ret;
}

uintptr_t pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; uintptr_t ret = 0;

    if(thread_handle == get_current_thread()) {
        return get_current_process_id();
    }

    if(duplicate_handle(get_current_process(), thread_handle,
            get_current_process(), &thread_handle, THREAD_QUERY_INFORMATION,
            FALSE, 0) == FALSE) {
        return 0;
    }

    uint32_t length = query_information_thread(thread_handle,
        ThreadBasicInformation, &tbi, sizeof(tbi));
    if(length == sizeof(tbi)) {
        ret = (uintptr_t) tbi.ClientId.UniqueProcess;
    }

    close_handle(thread_handle);
    return ret;
}

uintptr_t tid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; uintptr_t ret = 0;

    if(duplicate_handle(get_current_process(), thread_handle,
            get_current_process(), &thread_handle, THREAD_QUERY_INFORMATION,
            FALSE, 0) == FALSE) {
        return 0;
    }

    uint32_t length = query_information_thread(thread_handle,
        ThreadBasicInformation, &tbi, sizeof(tbi));
    if(length == sizeof(tbi)) {
        ret = (uintptr_t) tbi.ClientId.UniqueThread;
    }

    close_handle(thread_handle);
    return ret;
}

uintptr_t parent_process_id()
{
    PROCESS_BASIC_INFORMATION pbi;

    uint32_t length = query_information_process(get_current_process(),
        ProcessBasicInformation, &pbi, sizeof(pbi));
    if(length == sizeof(pbi)) {
        return (uintptr_t) pbi.InheritedFromUniqueProcessId;
    }
    return 0;
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

void wcsncpyA(wchar_t *dst, const char *src, uint32_t length)
{
    while (*src != 0 && length > 1) {
        *dst++ = *src++, length--;
    }
    *dst = 0;
}

int copy_unicode_string(const UNICODE_STRING *in,
    UNICODE_STRING *out, wchar_t *buffer, uint32_t length)
{
    memset(out, 0, sizeof(UNICODE_STRING));

    if(in != NULL && in->Buffer != NULL) {
        out->Buffer = buffer;
        out->Length = in->Length;
        out->MaximumLength = length;

        memcpy(out->Buffer, in->Buffer, in->Length);
        out->Buffer[in->Length / sizeof(wchar_t)] = 0;
        return 0;
    }
    return -1;
}

wchar_t *extract_unicode_string(const UNICODE_STRING *unistr)
{
    wchar_t *ret = get_unicode_buffer();

    if(unistr != NULL && unistr->Buffer != NULL) {
        memcpy(ret, unistr->Buffer, unistr->Length);
        ret[unistr->Length / sizeof(wchar_t)] = 0;
        return ret;
    }
    return NULL;
}

int copy_object_attributes(const OBJECT_ATTRIBUTES *in,
    OBJECT_ATTRIBUTES *out, UNICODE_STRING *unistr,
    wchar_t *buffer, uint32_t length)
{
    memset(out, 0, sizeof(OBJECT_ATTRIBUTES));

    if(in != NULL && in->Length == sizeof(OBJECT_ATTRIBUTES)) {
        out->Length = in->Length;
        out->RootDirectory = in->RootDirectory;
        out->Attributes = in->Attributes;
        out->SecurityDescriptor = in->SecurityDescriptor;
        out->SecurityQualityOfService = in->SecurityQualityOfService;
        out->ObjectName = NULL;

        if(in->ObjectName != NULL) {
            out->ObjectName = unistr;
            return copy_unicode_string(in->ObjectName,
                unistr, buffer, length);
        }
        return 0;
    }
    return -1;
}

static uint32_t _path_from_handle(HANDLE handle, wchar_t *path)
{
    OBJECT_NAME_INFORMATION *object_name = (OBJECT_NAME_INFORMATION *)
        mem_alloc(OBJECT_NAME_INFORMATION_REQUIRED_SIZE);
    if(object_name == NULL) return 0;

    uint32_t length = query_object(handle, ObjectNameInformation,
        object_name, OBJECT_NAME_INFORMATION_REQUIRED_SIZE);
    if(length == 0) {
        mem_free(object_name);
        return 0;
    }

    memcpy(path, object_name->Name.Buffer, object_name->Name.Length);
    path[object_name->Name.Length / sizeof(wchar_t)] = 0;

    mem_free(object_name);
    return lstrlenW(path);
}

static uint32_t _path_from_unicode_string(const UNICODE_STRING *unistr,
    wchar_t *path, uint32_t length)
{
    if(unistr != NULL && unistr->Buffer != NULL && unistr->Length != 0) {
        length = MIN(unistr->Length / sizeof(wchar_t), length);

        memcpy(path, unistr->Buffer, length * sizeof(wchar_t));
        path[length] = 0;
        return length;
    }
    return 0;
}

static uint32_t _path_from_object_attributes(
    const OBJECT_ATTRIBUTES *obj, wchar_t *path)
{
    if(obj == NULL) {
        return 0;
    }

    uint32_t offset = _path_from_handle(obj->RootDirectory, path);

    // Only append the backslash if both root directory and object name have
    // been set.
    if(offset != 0 && obj->ObjectName != NULL &&
            obj->ObjectName->Buffer != NULL && obj->ObjectName->Length != 0) {
        path[offset++] = '\\';
    }

    return offset + _path_from_unicode_string(obj->ObjectName,
        &path[offset], MAX_PATH_W - offset);
}

uint32_t path_get_full_pathA(const char *in, wchar_t *out)
{
    wchar_t input[MAX_PATH+1];

    if(in == NULL) {
        out[0] = 0;
        return 0;
    }

    wcsncpyA(input, in, MAX_PATH+1);
    return path_get_full_pathW(input, out);
}

static inline void swap(wchar_t **a, wchar_t **b)
{
    wchar_t *tmp = *a;
    *a = *b;
    *b = tmp;
}

uint32_t path_get_full_pathW(const wchar_t *in, wchar_t *out)
{
    if(in == NULL) {
        out[0] = 0;
        return 0;
    }

    wchar_t *buf1 = get_unicode_buffer(), *buf2 = get_unicode_buffer();
    wchar_t *pathi, *patho, *last_ptr = NULL;

    wcscpy(buf1, in);
    pathi = buf1, patho = buf2;

    // Globalroot is an optional prefix that can be skipped.
    if(wcsnicmp(pathi, L"\\??\\Globalroot\\", 15) == 0) {
        wcscpy(patho, pathi + 15);
        swap(&pathi, &patho);
    }

    // Check whether any of the known aliases are being used.
    for (uint32_t idx = 0; idx < g_alias_index; idx++) {
        uint32_t length = lstrlenW(g_aliases[idx][0]);
        if(wcsnicmp(pathi, g_aliases[idx][0], length) == 0) {
            wcscpy(patho, g_aliases[idx][1]);
            wcsncat(patho, &pathi[length], MAX_PATH_W+1 - lstrlenW(patho));
            swap(&pathi, &patho);
            break;
        }
    }

    // Normalize the input file path.
    if(wcsncmp(pathi, L"\\??\\", 4) == 0 ||
            wcsncmp(pathi, L"\\\\?\\", 4) == 0) {
        memcpy(pathi, L"\\\\?\\", 4 * sizeof(wchar_t));
    }
    // If the path starts with "C:\\" or similar then it's an absolute
    // path and we should prepend "\\\\?\\".
    else if(pathi[1] == ':' && pathi[2] == '\\') {
        wcscpy(patho, L"\\\\?\\");
        wcsncat(patho, pathi, MAX_PATH_W+1 - 4);
        swap(&pathi, &patho);
    }

    // We don't further modify ignored filepaths.
    if(is_ignored_filepath(pathi) != 0) {
        wcscpy(out, pathi);
        free_unicode_buffer(buf1);
        free_unicode_buffer(buf2);
        return lstrlenW(out);
    }

    // Try to obtain the full path. If this fails, then we don't do any
    // further modifications to the path as it is not an actual file.
    if(GetFullPathNameW(pathi, MAX_PATH_W+1, patho, NULL) == 0) {
        // Ignore the "\\\\?\\" part.
        if(wcsnicmp(pathi, L"\\\\?\\", 4) == 0) {
            wcscpy(out, pathi + 4);
        }
        else {
            wcscpy(out, pathi);
        }
        free_unicode_buffer(buf1);
        free_unicode_buffer(buf2);
        return lstrlenW(out);
    }

    swap(&pathi, &patho);

    wchar_t *baseptr = pathi;
    if(wcsnicmp(pathi, L"\\\\?\\", 4) == 0) {
        baseptr = &pathi[4];
    }

    // Find the longest path that we can query as long path and use that to
    // craft our final path.
    while (1) {
        // Ignore the "\\\\?\\" part.
        wchar_t *ptr = wcsrchr(baseptr, '\\');
        if(ptr == NULL) {
            // No matches, copy the whole thing over.
            if(last_ptr != NULL) {
                *last_ptr = '\\';
            }

            wcscpy(out, baseptr);
            free_unicode_buffer(buf1);
            free_unicode_buffer(buf2);
            return lstrlenW(out);
        }

        if(last_ptr != NULL) {
            *last_ptr = '\\';
            *ptr = 0;
        }

        if(GetLongPathNameW(pathi, patho, MAX_PATH_W+1) != 0) {
            // Copy the first part except for the "\\\\?\\" part.
            if(wcsnicmp(patho, L"\\\\?\\", 4) == 0) {
                wcscpy(out, patho + 4);
            }
            else {
                wcscpy(out, patho);
            }

            // Only append the remainder if this is not the full path.
            if(last_ptr != NULL) {
                // Everything that's behind the long path that we found
                // including directory seperator.
                *ptr = '\\';
                wcscat(out, ptr);
            }
            free_unicode_buffer(buf1);
            free_unicode_buffer(buf2);
            return lstrlenW(out);
        }

        last_ptr = ptr;
    }
}

uint32_t path_get_full_path_handle(HANDLE file_handle, wchar_t *out)
{
    wchar_t *input = get_unicode_buffer(); uint32_t ret = 0;

    if(_path_from_handle(file_handle, input) != 0) {
        ret = path_get_full_pathW(input, out);
    }
    else {
        out[0] = 0;
    }

    free_unicode_buffer(input);
    return ret;
}

uint32_t path_get_full_path_unistr(const UNICODE_STRING *in, wchar_t *out)
{
    wchar_t *input = get_unicode_buffer(); uint32_t ret = 0;

    if(in != NULL && in->Buffer != NULL) {
        memcpy(input, in->Buffer, in->Length);
        input[in->Length / sizeof(wchar_t)] = 0;
        ret = path_get_full_pathW(input, out);
    }
    else {
        out[0] = 0;
    }

    free_unicode_buffer(input);
    return ret;
}

uint32_t path_get_full_path_objattr(const OBJECT_ATTRIBUTES *in, wchar_t *out)
{
    wchar_t *input = get_unicode_buffer(); uint32_t ret = 0;

    if(_path_from_object_attributes(in, input) != 0) {
        ret = path_get_full_pathW(input, out);
    }
    else {
        out[0] = 0;
    }

    free_unicode_buffer(input);
    return ret;
}

static uint32_t _reg_root_handle(HANDLE key_handle, wchar_t *regkey)
{
    const wchar_t *key = NULL;
    switch ((uintptr_t) key_handle) {
    case (uintptr_t) HKEY_CLASSES_ROOT:
        key = L"HKEY_CLASSES_ROOT";
        break;

    case (uintptr_t) HKEY_CURRENT_USER:
        key = L"HKEY_CURRENT_USER";
        break;

    case (uintptr_t) HKEY_LOCAL_MACHINE:
        key = L"HKEY_LOCAL_MACHINE";
        break;

    case (uintptr_t) HKEY_USERS:
        key = L"HKEY_USERS";
        break;

    case (uintptr_t) HKEY_PERFORMANCE_DATA:
        key = L"HKEY_PERFORMANCE_DATA";
        break;

    case (uintptr_t) HKEY_CURRENT_CONFIG:
        key = L"HKEY_CURRENT_CONFIG";
        break;

    case (uintptr_t) HKEY_DYN_DATA:
        key = L"HKEY_DYN_DATA";
        break;
    }

    if(key != NULL) {
        uint32_t length = lstrlenW(key);
        memmove(regkey, key, length * sizeof(wchar_t));
        return length;
    }
    return 0;
}

static uint32_t _reg_key_normalize(wchar_t *regkey)
{
    uint32_t length = 0;

    // TODO Add support for handling null-bytes in registry keys.
    for (wchar_t *in = regkey, *out = regkey; *in != 0;
            in++, out++, length++) {
        // Ignore superfluous backslashes.
        while (*in == '\\' && in[1] == '\\') {
            in++;
        }

        *out = *in;
    }

    regkey[length] = 0;

    // \\REGISTRY\\USER\\S-1-5-<SID of user> is just another way of writing
    // HKEY_CURRENT_USER, so we normalize it.
    if(wcsnicmp(regkey, HKCU_PREFIX, lstrlenW(HKCU_PREFIX)) == 0) {
        const wchar_t *subkey = wcschr(regkey + lstrlenW(HKCU_PREFIX), '\\');
        uint32_t offset = _reg_root_handle(HKEY_CURRENT_USER, regkey);

        // Shouldn't be a null pointer but let's just make sure.
        if(subkey != NULL && length != 0) {
            // Subtract the part of the key from the length that
            // we're skipping.
            length -= subkey - regkey;

            memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
            regkey[offset + length] = 0;
            return offset + length;
        }

        regkey[offset] = 0;
        return offset;
    }

    // HKEY_USERS\\S-1-5-<SID of user> is just another way of writing
    // HKEY_CURRENT_USER, so we normalize it.
    if(wcsnicmp(regkey, HKCU_PREFIX2, lstrlenW(HKCU_PREFIX2)) == 0) {
        const wchar_t *subkey = wcschr(regkey + lstrlenW(HKCU_PREFIX2), '\\');
        uint32_t offset = _reg_root_handle(HKEY_CURRENT_USER, regkey);

        // Shouldn't be a null pointer but let's just make sure.
        if(subkey != NULL && length != 0) {
            // Subtract the part of the key from the length that
            // we're skipping.
            length -= subkey - regkey;

            memmove(&regkey[offset], subkey, length * sizeof(wchar_t));
            regkey[offset + length] = 0;
            return offset + length;
        }

        regkey[offset] = 0;
        return offset;
    }

    // HKEY_LOCAL_MACHINE might be expanded into \\REGISTRY\\MACHINE - we
    // normalize this as well.
    if(wcsnicmp(regkey, HKLM_PREFIX, lstrlenW(HKLM_PREFIX)) == 0) {
        const wchar_t *subkey = &regkey[lstrlenW(HKLM_PREFIX)];

        // Subtract the part of the key from the length that
        // we're skipping.
        length -= lstrlenW(HKLM_PREFIX);

        // Because "HKEY_LOCAL_MACHINE" is actually a longer string than
        // "\\REGISTRY\\MACHINE" we first move the subkey and only then
        // write the HKEY_LOCAL_MACHINE prefix.
        memmove(regkey + lstrlenW(L"HKEY_LOCAL_MACHINE"),
            subkey, length * sizeof(wchar_t));

        // The HKEY_LOCAL_MACHINE prefix.
        length += _reg_root_handle(HKEY_LOCAL_MACHINE, regkey);

        regkey[length] = 0;
        return length;
    }
    return lstrlenW(regkey);
}

uint32_t reg_get_key(HANDLE key_handle, wchar_t *regkey)
{
    uint32_t buffer_length =
        sizeof(KEY_NAME_INFORMATION) + MAX_PATH_W * sizeof(wchar_t);

    uint32_t offset = _reg_root_handle(key_handle, regkey);
    if(offset != 0) {
        regkey[offset] = 0;
        return offset;
    }

    KEY_NAME_INFORMATION *key_name_information =
        (KEY_NAME_INFORMATION *) mem_alloc(buffer_length);
    if(key_name_information == NULL) return 0;

    if(query_key(key_handle, KeyNameInformation,
                key_name_information, buffer_length) != 0) {
        if(key_name_information->NameLength > MAX_PATH_W * sizeof(wchar_t)) {
            pipe("CRITICAL:Registry key too long?! regkey length: %d",
                key_name_information->NameLength / sizeof(wchar_t));
            mem_free(key_name_information);
            return 0;
        }

        uint32_t length = key_name_information->NameLength / sizeof(wchar_t);
        memcpy(&regkey[offset], key_name_information->Name,
            length * sizeof(wchar_t));
        regkey[offset + length] = 0;

        mem_free(key_name_information);
        return _reg_key_normalize(regkey);
    }
    mem_free(key_name_information);
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

    regkey[offset++] = '\\';

    length = MIN(length+1, MAX_PATH_W+1 - offset);
    wcsncpyA(&regkey[offset], subkey, length);
    return _reg_key_normalize(regkey);
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
    return _reg_key_normalize(regkey);
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

void reg_get_info_from_keyvalue(const void *buf, uint32_t length,
    KEY_VALUE_INFORMATION_CLASS information_class, wchar_t **reg_name,
    uint32_t *reg_type, uint32_t *data_length, uint8_t **data)
{
    // TODO Length checking.
    (void) length;

    if(buf == NULL) {
        return;
    }

    switch (information_class) {
    case KeyValueBasicInformation: {
        KEY_VALUE_BASIC_INFORMATION *basic =
            (KEY_VALUE_BASIC_INFORMATION *) buf;

        *reg_name = get_unicode_buffer();
        uint32_t length = MIN(
            basic->NameLength, MAX_PATH_W * sizeof(wchar_t));
        memcpy(*reg_name, basic->Name, length);
        (*reg_name)[length] = 0;

        *reg_type = basic->Type;
        break;
    }

    case KeyValueFullInformation: case KeyValueFullInformationAlign64: {
        KEY_VALUE_FULL_INFORMATION *full =
            (KEY_VALUE_FULL_INFORMATION *) buf;

        *reg_name = get_unicode_buffer();
        uint32_t length = MIN(
            full->NameLength, MAX_PATH_W * sizeof(wchar_t));
        memcpy(*reg_name, full->Name, length);
        (*reg_name)[length] = 0;

        *reg_type = full->Type;
        *data_length = full->DataLength;
        *data = (uint8_t *) full + full->DataOffset;
        break;
    }

    case KeyValuePartialInformation: case KeyValuePartialInformationAlign64: {
        KEY_VALUE_PARTIAL_INFORMATION *partial =
            (KEY_VALUE_PARTIAL_INFORMATION *) buf;

        *reg_name = NULL;
        *reg_type = partial->Type;
        *data_length = partial->DataLength;
        *data = partial->Data;
        break;
    }

    case MaxKeyValueInfoClass:
        break;
    }
}

const char *our_inet_ntoa(struct in_addr ipaddr)
{
    static char ip[32];
    our_snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
        ipaddr.s_addr & 0xff, (ipaddr.s_addr >> 8) & 0xff,
        (ipaddr.s_addr >> 16) & 0xff, (ipaddr.s_addr >> 24) & 0xff);
    return ip;
}

uint16_t our_htons(uint16_t value)
{
    return ((value & 0xff) << 8) | ((value >> 8) & 0xff);
}

uint32_t our_htonl(uint32_t value)
{
    return
        (((value >>  0) & 0xff) << 24) |
        (((value >>  8) & 0xff) << 16) |
        (((value >> 16) & 0xff) <<  8) |
        (((value >> 24) & 0xff) <<  0);
}

void get_ip_port(const struct sockaddr *addr, const char **ip, int *port)
{
    if(addr == NULL) return;

    // TODO IPv6 support.
    if(addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
        *ip = our_inet_ntoa(addr4->sin_addr);
        *port = our_htons(addr4->sin_port);
    }
}

int is_shutting_down()
{
    HANDLE mutex_handle = OpenMutex(SYNCHRONIZE, FALSE, g_shutdown_mutex);
    if(mutex_handle != NULL) {
        close_handle(mutex_handle);
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
        if(stricmp(&library[length - 4], ".dll") == 0) {
            library[length - 4] = 0;
        }
    }
}

#if __x86_64__

int stacktrace(CONTEXT *ctx, uintptr_t *addrs, uint32_t length)
{
    uint32_t count = 0; uintptr_t image_base, establisher_frame;
    RUNTIME_FUNCTION *runtime_function; void *handler_data; CONTEXT _ctx;

    if(ctx == NULL) {
        ctx = &_ctx;
        RtlCaptureContext(&_ctx);
    }

    while (count < length && ctx->Rip != 0) {
        addrs[count++] = ctx->Rip;

        // This function calls NtQueryVirtualMemory() under the hood. If any
        // stack overflows occur due to recursion issues, this is probably
        // the issue. Can be solved, if required, by returning early from
        // the NtQueryVirtualMemory() hook handler.
        runtime_function =
            RtlLookupFunctionEntry(ctx->Rip, &image_base, NULL);
        if(runtime_function == NULL) {
            ctx->Rip = *(uintptr_t *) ctx->Rsp;
            ctx->Rsp += 8;
        }
        else {
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx->Rip,
                runtime_function, ctx, &handler_data, &establisher_frame,
                NULL);
        }
    }

    return count;
}

#else

int stacktrace(CONTEXT *ctx, uintptr_t *addrs, uint32_t length)
{
    uint32_t top = readtls(0x04) - 2 * sizeof(uint32_t);
    uint32_t bottom = readtls(0x08);
    uint32_t count = 0, ebp = get_ebp();

    if(ctx != NULL) {
        ebp = ctx->Ebp;
    }

    for (; count < length && ebp >= bottom && ebp < top; count++) {
        uintptr_t addr = *(uint32_t *)(ebp + 4);
        ebp = *(uint32_t *) ebp;

        addrs[count] = addr;

        // No need to track any further.
        if(addrs[count] == 0) {
            break;
        }
    }
    return count;
}

#endif

static LONG CALLBACK _exception_handler(
    EXCEPTION_POINTERS *exception_pointers)
{
    uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;

    count = stacktrace(exception_pointers->ContextRecord, addrs, RETADDRCNT);

    log_exception(exception_pointers->ContextRecord,
        exception_pointers->ExceptionRecord, addrs, count);

    return EXCEPTION_CONTINUE_SEARCH;
}

void *memdup(const void *addr, uint32_t length)
{
    if(addr != NULL && length != 0) {
        void *ret = mem_alloc(length);
        if(ret != NULL) {
            memcpy(ret, addr, length);
            return ret;
        }
    }
    return NULL;
}

wchar_t *wcsdup(const wchar_t *s)
{
    if(s != NULL) {
        return memdup(s, (lstrlenW(s) + 1) * sizeof(wchar_t));
    }
    return NULL;
}

int page_is_readable(const uint8_t *addr)
{
    MEMORY_BASIC_INFORMATION_CROSS mbi;
    return virtual_query(addr, &mbi) != FALSE &&
        mbi.State & MEM_COMMIT && mbi.Protect & PAGE_READABLE;
}

void clsid_to_string(REFCLSID rclsid, wchar_t *buf)
{
    LPOLESTR ptr; *buf = 0;

    if(StringFromCLSID(rclsid, &ptr) == S_OK) {
        wcscpy(buf, ptr);
        CoTaskMemFree(ptr);
    }
}

void wsabuf_get_buffer(uint32_t buffer_count, const WSABUF *buffers,
    uint8_t **ptr, uint32_t *length)
{
    *length = 0;
    for (uint32_t idx = 0; idx < buffer_count; idx++) {
        *length += buffers[idx].len;
    }

    *ptr = (uint8_t *) mem_alloc(*length);
    if(*ptr != NULL) {
        for (uint32_t idx = 0, offset = 0; idx < buffer_count; idx++) {
            if(buffers[idx].buf != NULL && buffers[idx].len != 0) {
                memcpy(&(*ptr)[offset], buffers[idx].buf, buffers[idx].len);
                offset += buffers[idx].len;
            }
        }
    }
}

uint64_t hash_buffer(const void *buf, uint32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    const uint8_t *p = (const uint8_t *) buf;
    uint64_t ret = *p << 7;
    for (uint32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ *p++;
    }
    return ret ^ length;
}

uint64_t hash_string(const char *buf, int32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    if(length < 0) {
        length = strlen(buf);
    }

    uint64_t ret = *buf << 7;
    for (int32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ (uint8_t) *buf++;
    }
    return ret ^ length;
}

uint64_t hash_stringW(const wchar_t *buf, int32_t length)
{
    if(buf == NULL || length == 0) {
        return 0;
    }

    if(length < 0) {
        length = lstrlenW(buf);
    }

    uint64_t ret = *buf << 7;
    for (int32_t idx = 0; idx < length; idx++) {
        ret = (ret * 1000003) ^ (uint16_t) *buf++;
    }
    return ret ^ length;
}

uint64_t hash_uint64(uint64_t value)
{
    return hash_buffer(&value, sizeof(value));
}

// http://stackoverflow.com/questions/9655202/how-to-convert-integer-to-string-in-c
int ultostr(intptr_t value, char *str, int base)
{
    const char charset[] = "0123456789abcdef"; int length = 0;

    // Negative values.
    if(value < 0 && base == 10) {
        *str++ = '-', length++;
        value = -value;
    }

    // Calculate the amount of numbers required.
    uintptr_t shifter = value, uvalue = value;
    do {
        str++, length++, shifter /= base;
    } while (shifter);

    // Populate the string.
    *str = 0;
    do {
        *--str = charset[uvalue % base];
        uvalue /= base;
    } while (uvalue);
    return length;
}

static uintptr_t _min(uintptr_t a, uintptr_t b)
{
    return a < b ? a : b;
}

int our_vsnprintf(char *buf, int length, const char *fmt, va_list args)
{
    const char *base = buf;
    for (; *fmt != 0 && length > 1; fmt++) {
        if(*fmt != '%') {
            *buf++ = *fmt, length--;
            continue;
        }

        const char *s; char tmp[32]; uintptr_t p; intptr_t v, l;

        switch (*++fmt) {
        case 's':
            s = va_arg(args, const char *);
            strncpy(buf, s, length-1);
            l = _min(length-1, strlen(s));
            buf += l, length -= l;
            break;

        case 'p':
            p = va_arg(args, uintptr_t);
            if(length > 10) {
                *buf++ = '0', *buf++ = 'x';
                l = ultostr(p, buf, 16);
                length -= 2 + l, buf += l;
            }
            break;

        case 'd':
            v = va_arg(args, intptr_t);
            l = ultostr(v >= 0 ? v : -v, tmp, 10);
            if(length > l + (v < 0)) {
                if(v < 0) {
                    v = -v, *buf++ = '-', length--;
                }
                l = ultostr(v, buf, 10);
                length -= l, buf += l;
            }
            break;

        default:
            dpipe("CRITICAL:Unhandled vsnprintf modifier: %s", 4, fmt);
        }
    }
    *buf = 0;
    return buf - base;
}

int our_snprintf(char *buf, int length, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    int ret = our_vsnprintf(buf, length, fmt, args);

    va_end(args);
    return ret;
}
