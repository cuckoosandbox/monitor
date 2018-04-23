/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2014-2018 Cuckoo Foundation.

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
#include <tlhelp32.h>
#include "bson/bson.h"
#include "hooking.h"
#include "ignore.h"
#include "log.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"
#include "sha1.h"
#include "symbol.h"

static char g_shutdown_mutex[MAX_PATH];
static array_t g_unicode_buffer_ptr_array;
static array_t g_unicode_buffer_use_array;

static monitor_hook_t g_hook_library;
static monitor_hook_t g_unhook_library;

#define HKCU_PREFIX  L"\\REGISTRY\\USER\\S-1-5-"
#define HKCU_PREFIX2 L"HKEY_USERS\\S-1-5-"
#define HKLM_PREFIX  L"\\REGISTRY\\MACHINE"

static wchar_t g_aliases[64][2][MAX_PATH];
static uint32_t g_alias_index;

static uintptr_t g_exception_addrs[32];
static uint32_t g_exception_addr_count;

void find_exception_addresses(uintptr_t *addresses, uint32_t *count);

uint32_t g_monitor_track;
uint32_t g_monitor_mode;

static uint32_t g_monitor_trigger_mode;
static wchar_t g_monitor_trigger[MAX_PATH]; // TODO Switch to MAX_PATH_W?
int g_monitor_logging;

#define ADD_ALIAS(before, after) \
    if(g_alias_index == 64) { \
        pipe("CRITICAL:Too many aliases!"); \
        exit(1); \
    } \
    wcscpy(g_aliases[g_alias_index][0], before); \
    wcscpy(g_aliases[g_alias_index][1], after); \
    g_alias_index++;

int misc_init(const char *shutdown_mutex)
{
    strncpy(g_shutdown_mutex, shutdown_mutex, sizeof(g_shutdown_mutex));

    // TODO Replace custom unicode buffer logic by implementing free() support
    // to our slab allocator (which is actually what a slab allocator is
    // supposed to do, afaik).
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
    return 0;
}

int misc_init2(monitor_hook_t monitor_hook, monitor_hook_t monitor_unhook)
{
    g_hook_library = monitor_hook;
    g_unhook_library = monitor_unhook;

    find_exception_addresses(g_exception_addrs, &g_exception_addr_count);
    return 0;
}

void hook_library(const char *library, void *module_handle)
{
    g_hook_library(library, module_handle);
}

void unhook_library(const char *library, void *module_handle)
{
    g_unhook_library(library, module_handle);
}

void misc_set_monitor_options(uint32_t track, uint32_t mode,
    const wchar_t *trigger)
{
    g_monitor_track = track;
    g_monitor_mode = mode;
    g_monitor_logging = 1;

    g_monitor_trigger_mode = CONFIG_TRIGGER_NONE;

    if(wcsncmp(trigger, L"file:", 5) == 0) {
        g_monitor_logging = 0;
        g_monitor_trigger_mode = CONFIG_TRIGGER_FILE;
        path_get_full_pathW(&trigger[5], g_monitor_trigger);
    }
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
                pipe("WARNING:Error allocating memory for unicode buffer");
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
    if(ptr == NULL) {
        return;
    }

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

uint32_t pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi; uint32_t ret = 0;

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

uint32_t pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; uint32_t ret = 0;

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
        ret = (uint32_t) (uintptr_t) tbi.ClientId.UniqueProcess;
    }

    close_handle(thread_handle);
    return ret;
}

uint32_t tid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi; uint32_t ret = 0;

    if(duplicate_handle(get_current_process(), thread_handle,
            get_current_process(), &thread_handle, THREAD_QUERY_INFORMATION,
            FALSE, 0) == FALSE) {
        return 0;
    }

    uint32_t length = query_information_thread(thread_handle,
        ThreadBasicInformation, &tbi, sizeof(tbi));
    if(length == sizeof(tbi)) {
        ret = (uint32_t) (uintptr_t) tbi.ClientId.UniqueThread;
    }

    close_handle(thread_handle);
    return ret;
}

uint32_t parent_process_identifier()
{
    PROCESS_BASIC_INFORMATION pbi;

    uint32_t length = query_information_process(get_current_process(),
        ProcessBasicInformation, &pbi, sizeof(pbi));
    if(length == sizeof(pbi)) {
        return (uint32_t) (uintptr_t) pbi.InheritedFromUniqueProcessId;
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
    LDR_MODULE *mod; PEB *peb = get_peb();

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

const wchar_t *get_module_file_name(HMODULE module_handle)
{
    LDR_MODULE *mod, *first_mod; PEB *peb = get_peb();

    first_mod = mod =
        (LDR_MODULE *) peb->LoaderData->InLoadOrderModuleList.Flink;

    // Basic sanity checks. At the very most we want to iterate a couple
    // thousand times through the list - this should be more than enough.
    // Furthermore stop iterating if the first node is found again.
    for (uint32_t idx = 0; idx < 0x1000 && mod->BaseAddress != NULL; idx++) {
        if(mod->BaseAddress == module_handle) {
            return mod->BaseDllName.Buffer;
        }

        mod = (LDR_MODULE *) mod->InLoadOrderModuleList.Flink;
        if(mod == first_mod) {
            break;
        }
    }
    return NULL;
}

void loaded_modules_enumerate(bson *b)
{
    LDR_MODULE *mod, *first_mod; char index[8], buf[32]; PEB *peb = get_peb();

    first_mod = mod =
        (LDR_MODULE *) peb->LoaderData->InLoadOrderModuleList.Flink;

    for (uint32_t idx = 0; idx < 0x1000 && mod->BaseAddress != NULL; idx++) {
        our_snprintf(index, sizeof(index), "%d", idx);
        bson_append_start_object(b, index);

        log_wstring(b, "filepath", mod->FullDllName.Buffer,
            mod->FullDllName.Length / sizeof(wchar_t));

        log_wstring(b, "basename", mod->BaseDllName.Buffer,
            mod->BaseDllName.Length / sizeof(wchar_t));

        our_snprintf(buf, sizeof(buf), "%p", mod->BaseAddress);
        log_string(b, "baseaddr", buf, strlen(buf));

        log_intptr(b, "imgsize", module_image_size(mod->BaseAddress));

        bson_append_finish_object(b);

        mod = (LDR_MODULE *) mod->InLoadOrderModuleList.Flink;
        if(mod == first_mod) {
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

wchar_t *extract_unicode_string_unistr(const UNICODE_STRING *unistr)
{
    wchar_t *ret = get_unicode_buffer(); UNICODE_STRING us;

    if(unistr == NULL || copy_bytes(&us, unistr, sizeof(us)) < 0) {
        free_unicode_buffer(ret);
        return NULL;
    }

    if(us.Buffer != NULL) {
        copy_bytes(ret, us.Buffer, us.Length);
        ret[us.Length / sizeof(wchar_t)] = 0;
        return ret;
    }

    free_unicode_buffer(ret);
    return NULL;
}

wchar_t *extract_unicode_string_objattr(const OBJECT_ATTRIBUTES *objattr)
{
    OBJECT_ATTRIBUTES obj;

    if(objattr == NULL || copy_bytes(&obj, objattr, sizeof(obj)) < 0) {
        return NULL;
    }

    return extract_unicode_string_unistr(obj.ObjectName);
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

        copy_bytes(path, unistr->Buffer, length * sizeof(wchar_t));
        path[length] = 0;
        return length;
    }
    return 0;
}

static uint32_t _path_from_object_attributes(
    const OBJECT_ATTRIBUTES *objattr, wchar_t *path)
{
    OBJECT_ATTRIBUTES obj; UNICODE_STRING us;

    if(objattr == NULL) {
        return 0;
    }

    if(copy_bytes(&obj, objattr, sizeof(OBJECT_ATTRIBUTES)) < 0) {
        return 0;
    }

    uint32_t offset = _path_from_handle(obj.RootDirectory, path);

    if(obj.ObjectName != NULL) {
        if(copy_bytes(&us, obj.ObjectName, sizeof(UNICODE_STRING)) < 0) {
            return offset;
        }

        if(offset != 0 && us.Buffer != NULL && us.Length != 0) {
            path[offset++] = '\\';
        }

        return offset + _path_from_unicode_string(&us,
            &path[offset], MAX_PATH_W - offset);
    }
    return offset;
}

uint32_t path_get_full_pathA(const char *in, wchar_t *out)
{
    wchar_t input[MAX_PATH+1];

    if(in == NULL) {
        out[0] = 0;
        return 0;
    }

    copy_wcsncpyA(input, in, MAX_PATH+1);
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

    if(copy_unicodez(buf1, in) < 0) {
        out[0] = 0;
        return 0;
    }

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

    // If a path starts with \??\ and doesn't have any further backslashes in
    // it, then we're looking at something like \??\hgfs or \??\vmci, and we
    // don't want to normalize that any further.
    if(wcsncmp(pathi, L"\\??\\", 4) == 0 && wcschr(pathi + 4, '\\') == NULL) {
        wcscpy(out, pathi);
        free_unicode_buffer(buf1);
        free_unicode_buffer(buf2);
        return lstrlenW(out);
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

        // uint32_t length = GetFullPathNameW(pathi, MAX_PATH_W + 1, patho, NULL);
        // if (length != 0) {
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
                // including directory separator.
                *ptr = '\\';
                wcscat(out, ptr);
            }
            free_unicode_buffer(buf1);
            free_unicode_buffer(buf2);
            return lstrlenW(out);
        }
        else {
            // *out = 0;
            // free_unicode_buffer(buf1);
            // free_unicode_buffer(buf2);
            // return 0;
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
    UNICODE_STRING us;

    if(in != NULL && copy_bytes(&us, in, sizeof(UNICODE_STRING)) == 0) {
        if(us.Buffer != NULL && us.Length != 0) {
            copy_bytes(input, us.Buffer, us.Length);
        }
        input[us.Length / sizeof(wchar_t)] = 0;
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
    copy_wcsncpyA(&regkey[offset], subkey, length);
    return _reg_key_normalize(regkey);
}

uint32_t reg_get_key_asciiz(HANDLE key_handle,
    const char *subkey, wchar_t *regkey)
{
    return reg_get_key_ascii(key_handle, subkey,
        subkey != NULL ? copy_strlen(subkey) : 0, regkey);
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
    copy_bytes(&regkey[offset], subkey, length * sizeof(wchar_t));
    regkey[offset + length] = 0;
    return _reg_key_normalize(regkey);
}

uint32_t reg_get_key_uniz(HANDLE key_handle,
    const wchar_t *subkey, wchar_t *regkey)
{
    return reg_get_key_uni(key_handle, subkey,
        subkey != NULL ? copy_strlenW(subkey) : 0, regkey);
}

uint32_t reg_get_key_unistr(HANDLE key_handle,
    const UNICODE_STRING *unistr, wchar_t *regkey)
{
    const wchar_t *ptr = NULL; uint32_t length = 0; UNICODE_STRING us;

    if(unistr != NULL &&
            copy_bytes(&us, unistr, sizeof(UNICODE_STRING)) == 0) {
        ptr = us.Buffer;
        length = us.Length / sizeof(wchar_t);
    }

    return reg_get_key_uni(key_handle, ptr, length, regkey);
}

uint32_t reg_get_key_objattr(
    const OBJECT_ATTRIBUTES *objattr, wchar_t *regkey)
{
    OBJECT_ATTRIBUTES obj;

    if(objattr == NULL ||
            copy_bytes(&obj, objattr, sizeof(OBJECT_ATTRIBUTES)) < 0) {
        return 0;
    }

    return reg_get_key_unistr(obj.RootDirectory, obj.ObjectName, regkey);
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

    // TODO Use the copy functions.
    switch (information_class) {
    case KeyValueBasicInformation: {
        KEY_VALUE_BASIC_INFORMATION *basic =
            (KEY_VALUE_BASIC_INFORMATION *) buf;

        *reg_name = get_unicode_buffer();
        uint32_t length = MIN(
            basic->NameLength, MAX_PATH_W * sizeof(wchar_t)
        );
        memcpy(*reg_name, basic->Name, length);
        (*reg_name)[length / sizeof(wchar_t)] = 0;

        *reg_type = basic->Type;
        break;
    }

    case KeyValueFullInformation: case KeyValueFullInformationAlign64: {
        KEY_VALUE_FULL_INFORMATION *full =
            (KEY_VALUE_FULL_INFORMATION *) buf;

        *reg_name = get_unicode_buffer();
        uint32_t length = MIN(
            full->NameLength, MAX_PATH_W * sizeof(wchar_t)
        );
        memcpy(*reg_name, full->Name, length);
        (*reg_name)[length / sizeof(wchar_t)] = 0;

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

void library_from_asciiz(const char *str, char *library, uint32_t length)
{
    memset(library, 0, length);

    if(str != NULL) {
        const char *libname = str;

        // Follow through all directories.
        for (const char *ptr = libname; *ptr != 0; ptr++) {
            if(*ptr == '\\' || *ptr == '/') {
                libname = ptr + 1;
            }
        }

        // Copy the library name into our ascii library buffer.
        length = MIN(length - 1, strlen(libname));
        for (uint32_t idx = 0; idx < length; idx++) {
            library[idx] = libname[idx];
        }

        // Strip off any remaining ".dll".
        if(stricmp(&library[length - 4], ".dll") == 0) {
            library[length - 4] = 0;
        }
    }
}

void library_from_unicodez(const wchar_t *str, char *library, int32_t length)
{
    memset(library, 0, length);

    if(str == NULL) {
        return;
    }

    // Follow through all directories.
    for (const wchar_t *ptr = str; *ptr != 0; ptr++) {
        if(*ptr == '\\' || *ptr == '/') {
            str = ptr + 1;
        }
    }

    // Copy the library name into our ascii library buffer.
    length = MIN(length - 1, lstrlenW(str));
    for (int32_t idx = 0; idx < length; idx++) {
        library[idx] = (char) str[idx];
    }

    // Strip off any remaining ".dll" or ".ocx" parts.
    if(stricmp(&library[length - 4], ".dll") == 0 ||
            stricmp(&library[length - 4], ".ocx") == 0) {
        library[length - 4] = 0;
    }
}

void library_from_unicode_string(const UNICODE_STRING *us,
    char *library, int32_t length)
{
    memset(library, 0, length);

    if(us != NULL) {
        return library_from_unicodez(us->Buffer, library, length);
    }
}

#if __x86_64__

int stacktrace(CONTEXT *ctx, uintptr_t *addrs, uint32_t length)
{
    uint32_t count = 0; uintptr_t image_base, establisher_frame;
    RUNTIME_FUNCTION *runtime_function; void *handler_data; CONTEXT _ctx;
    KNONVOLATILE_CONTEXT_POINTERS nv_ctx_ptrs;

    uintptr_t top = readtls(0x08) - 2 * sizeof(uintptr_t);
    uintptr_t bottom = readtls(0x10);

    if(ctx == NULL) {
        ctx = &_ctx;
        RtlCaptureContext(&_ctx);
    }

    while (count < length && ctx->Rip != 0 &&
            ctx->Rsp >= bottom && ctx->Rsp < top) {

        addrs[count++] = ctx->Rip;

        // Instructions can be up to 16 bytes in length.
        if(range_is_readable((uint8_t *) ctx->Rip, 16) == 0) {
            continue;
        }

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
            memset(&nv_ctx_ptrs, 0, sizeof(nv_ctx_ptrs));
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx->Rip,
                runtime_function, ctx, &handler_data, &establisher_frame,
                &nv_ctx_ptrs);
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

wchar_t *our_wcsdup(const wchar_t *s)
{
    if(s != NULL) {
        return memdup(s, (lstrlenW(s) + 1) * sizeof(wchar_t));
    }
    return NULL;
}

int page_is_readable(const void *addr)
{
    MEMORY_BASIC_INFORMATION_CROSS mbi;
    return virtual_query(addr, &mbi) != FALSE &&
        mbi.State & MEM_COMMIT && mbi.Protect & PAGE_READABLE;
}

int range_is_readable(const void *addr, uintptr_t size)
{
    MEMORY_BASIC_INFORMATION_CROSS mbi;
    const uint8_t *ptr = (const uint8_t *) addr;
    const uint8_t *end = ptr + size;

    while (ptr < end) {
        if(virtual_query(ptr, &mbi) == FALSE ||
                (mbi.State & MEM_COMMIT) == 0 ||
                (mbi.Protect & PAGE_READABLE) == 0) {
            return 0;
        }

        // Move to the next allocated page.
        ptr = (const uint8_t *) mbi.BaseAddress + mbi.RegionSize;
    }
    return 1;
}

void clsid_to_string(REFCLSID rclsid, char *buf)
{
    uint8_t ptr[16];

    if(copy_bytes(ptr, rclsid, 16) < 0) {
        *buf = 0;
        return;
    }

    our_snprintf(buf, 64, "{%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x}",
        ptr[3], ptr[2], ptr[1], ptr[0], ptr[5], ptr[4], ptr[7], ptr[6],
        ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
}

void wsabuf_get_buffer(uint32_t buffer_count, const WSABUF *buffers,
    uint8_t **ptr, uintptr_t *length)
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

void secbuf_get_buffer(uint32_t buffer_count, SecBuffer *buffers,
    uint8_t **ptr, uintptr_t *length)
{
    for (uint32_t idx = 0; idx < buffer_count; idx++) {
        if(buffers[idx].BufferType == SECBUFFER_DATA) {
            *ptr = buffers[idx].pvBuffer;
            *length = buffers[idx].cbBuffer;
            return;
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
int ultostr(int64_t value, char *str, int base)
{
    const char charset[] = "0123456789abcdef"; int length = 0;

    // Negative values.
    if(value < 0 && base == 10) {
        *str++ = '-', length++;
        value = -value;
    }

    // Calculate the amount of numbers required.
    uint64_t shifter = value, uvalue = value;
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

        case 'x':
            p = va_arg(args, uint32_t);
            if(length > 8) {
                l = ultostr(p, buf, 16);
                // Prepend a single '0' if uneven.
                if((l & 1) != 0) {
                    *buf++ = '0', length--;
                    l = ultostr(p, buf, 16);
                }
                length -= l, buf += l;
            }
            break;

        case 'd':
            v = va_arg(args, int32_t);
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

int our_memcmp(const void *a, const void *b, uint32_t length)
{
    const uint8_t *_a = (const uint8_t *) a, *_b = (const uint8_t *) b;
    for (; length != 0; _a++, _b++, length--) {
        if(*_a != *_b) {
            return *_a - *_b;
        }
    }
    return 0;
}

uint32_t our_strlen(const char *s)
{
    uint32_t ret = 0;
    while (*s != 0) {
        ret++, s++;
    }
    return ret;
}

void hexencode(char *dst, const uint8_t *src, uint32_t length)
{
    static const char charset[] = "0123456789abcdef";
    for (; length != 0; src++, length--) {
        *dst++ = charset[*src >> 4];
        *dst++ = charset[*src & 15];
    }
    *dst = 0;
}

void sha1(const void *buffer, uintptr_t buflen, char *hexdigest)
{
    SHA1Context ctx;
    SHA1Reset(&ctx);
    SHA1Input(&ctx, buffer, buflen);
    SHA1Result(&ctx);

    const uint32_t *digest = (const uint32_t *) ctx.Message_Digest;
    for (uint32_t idx = 0; idx < 5; idx++) {
        // TODO Our custom snprintf doesn't have proper %08x support yet.
        hexdigest += our_snprintf(hexdigest, 32, "%x%x%x%x",
            (digest[idx] >> 24) & 0xff,
            (digest[idx] >> 16) & 0xff,
            (digest[idx] >>  8) & 0xff,
            (digest[idx] >>  0) & 0xff);
    }
}

// Various Windows functions feature a string parameter which can also be a
// 16-bit integer given that all but the low 16-bits are zero.
void int_or_strA(char **ptr, const char *str, char *numbuf)
{
    *ptr = (char *) str;

    if(((uintptr_t) str & 0xffff) == (uintptr_t) str) {
        our_snprintf(numbuf, 10, "#%d", (uint16_t)(uintptr_t) str);
        *ptr = numbuf;
    }
}

void int_or_strW(wchar_t **ptr, const wchar_t *str, wchar_t *numbuf)
{
    char temp[10]; *ptr = (wchar_t *) str;

    if(((uintptr_t) str & 0xffff) == (uintptr_t) str) {
        our_snprintf(temp, 10, "#%d", (uint16_t)(uintptr_t) str);
        wcsncpyA(numbuf, temp, sizeof(temp));
        *ptr = numbuf;
    }
}

uint8_t *our_memmem(
    uint8_t *haystack, uint32_t haylength,
    const void *needle, uint32_t needlength,
    uint32_t *idx)
{
    uint32_t _idx = 0;

    if(idx == NULL) {
        idx = &_idx;
    }

    if(haylength < needlength) {
        return NULL;
    }

    for (; *idx < haylength - needlength + 1; *idx += 1) {
        if(memcmp(&haystack[*idx], needle, needlength) == 0) {
            return &haystack[*idx];
        }
    }
    return NULL;
}

wchar_t *our_memmemW(
    const void *haystack, uint32_t haylength,
    const wchar_t *needle, uint32_t *idx)
{
    return (wchar_t *) our_memmem((uint8_t *) haystack, haylength,
        needle, lstrlenW(needle) * sizeof(wchar_t), idx);
}

uint32_t sys_string_length(const BSTR bstr)
{
    if(bstr != NULL) {
        return *((uint32_t *) bstr - 1) / sizeof(wchar_t);
    }
    return 0;
}

BSTR sys_alloc_string_len(const OLECHAR *sz, UINT ui)
{
    static FARPROC pSysAllocStringLen;

    if(pSysAllocStringLen == NULL) {
        HMODULE module_handle = GetModuleHandle("oleaut32");
        if(module_handle != NULL) {
            pSysAllocStringLen =
                GetProcAddress(module_handle, "SysAllocStringLen");
        }
        if(pSysAllocStringLen == NULL) {
            return NULL;
        }
    }

    return (BSTR) pSysAllocStringLen(sz, ui);
}

int sys_string_cmp(const BSTR bstr, const wchar_t *value)
{
    if((intptr_t) sys_string_length(bstr) != lstrlenW(value)) {
        return -1;
    }

    return wcsncmp(bstr, value, sys_string_length(bstr));
}

HRESULT variant_change_type(
    VARIANTARG *dst, const VARIANTARG *src, USHORT flags, VARTYPE vt)
{
    static FARPROC pVariantChangeType;

    if(pVariantChangeType == NULL) {
        HMODULE module_handle = GetModuleHandle("oleaut32");
        if(module_handle != NULL) {
            pVariantChangeType =
                GetProcAddress(module_handle, "VariantChangeType");
        }
        if(pVariantChangeType == NULL) {
            return E_INVALIDARG;
        }
    }

    return pVariantChangeType(dst, src, flags, vt);
}

HRESULT variant_clear(VARIANTARG *arg)
{
    static FARPROC pVariantClear;

    if(pVariantClear == NULL) {
        HMODULE module_handle = GetModuleHandle("oleaut32");
        if(module_handle != NULL) {
            pVariantClear = GetProcAddress(module_handle, "VariantClear");
        }
        if(pVariantClear == NULL) {
            return E_INVALIDARG;
        }
    }

    return pVariantClear(arg);
}

HRESULT safe_array_destroy(SAFEARRAY *sa)
{
    static FARPROC pSafeArrayDestroy;

    if(pSafeArrayDestroy == NULL) {
        HMODULE module_handle = GetModuleHandle("oleaut32");
        if(module_handle != NULL) {
            pSafeArrayDestroy = GetProcAddress(
                module_handle, "SafeArrayDestroy"
            );
        }
        if(pSafeArrayDestroy == NULL) {
            return E_INVALIDARG;
        }
    }

    return pSafeArrayDestroy(sa);
}

static NTSTATUS g_exception_whitelist[] = {
    DBG_PRINTEXCEPTION_C,
    RPC_E_DISCONNECTED,
    STATUS_GUARD_PAGE_VIOLATION,
    STATUS_ENTRYPOINT_NOT_FOUND,
    0xe06d7363, // MSVC C++ Exception (0xe0000000 | "msc")
    0xe0000001, // STATUS_INSUFFICIENT_MEM
    0xe0000002, // STATUS_FILE_BAD_FORMAT
    0xe0434f4d, // .NET Exception (0xe0000000 | "COM")
    0xe0434352, // COM+ Exception (0xe0000000 | "CCR")
    0x406d1388, // MSDEV_SET_THREAD_NAME
    0xc004f012, // SL_E_VALUE_NOT_FOUND

#if DEBUG == 0
    // TODO Should we perhaps add some logging for this exception? This simply
    // happens every now and then, even without our additional code.
    EXCEPTION_STACK_OVERFLOW,
#endif
};

int is_exception_code_whitelisted(NTSTATUS exception_code)
{
    // There appears to be a soft limit of 16000 exceptions. We are not
    // interested in all of these exceptions as they are mostly used for
    // passing around information within Windows libraries. See also;
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx
    if((uint32_t) exception_code < 16000) {
        return 1;
    }

    for (uint32_t idx = 0;
            idx < sizeof(g_exception_whitelist)/sizeof(NTSTATUS); idx++) {
        if(exception_code == g_exception_whitelist[idx]) {
            return 1;
        }
    }
    return 0;
}

static funcoff_t _IsBadReadPtr1[] = {
    {0x4a5bdaad, 0x3df2b, 0},
    {0x4ce7baf9, 0x3d0ac, 0},
    {0x4ce7c78b, 0x4cb73, 0},
    {0x50b83c89, 0x3d09c, 0},
    {0x50b8479a, 0x4cb43, 0},
    {0x5632d5aa, 0x1b6a9, 0},
    {0x5632d9fd, 0x1256a, 0},
    {0, 0, 0},
};

static funcoff_t _IsBadReadPtr2[] = {
    {0x4a5bdaad, 0x685e9, 0},
    {0x4ce7baf9, 0x331e2, 0},
    {0x4ce7c78b, 0x4cba1, 0},
    {0x50b83c89, 0x331ca, 0},
    {0x50b8479a, 0x4cb71, 0},
    {0x5632d5aa, 0x1b6d7, 0},
    {0x5632d9fd, 0x125a9, 0},
    {0, 0, 0},
};

static mod2funcoff_t _kernel32[] = {
    {"IsBadReadPtr1", _IsBadReadPtr1},
    {"IsBadReadPtr2", _IsBadReadPtr2},
    {NULL, NULL},
};

// Manually locates "mov al, byte [eax]" and "mov al, byte [ecx]" instructions
// in the IsBadReadPtr function that cause false positive when executed as an
// access violation is raised.
void find_exception_addresses(uintptr_t *addresses, uint32_t *count)
{
    uint8_t *modaddr = (uint8_t *) GetModuleHandle("kernel32");
    for (mod2funcoff_t *p = _kernel32; p->funcname != NULL; p++) {
        uint8_t *ret = module_addr_timestamp(modaddr, 0, p->funcoff, NULL);
        if(ret != NULL) {
            addresses[*count] = (uintptr_t) ret;
            *count += 1;
        }
    }
}

int is_exception_address_whitelisted(uintptr_t addr)
{
    for (uint32_t idx = 0; idx < g_exception_addr_count; idx++) {
        if(g_exception_addrs[idx] == addr) {
            return 0;
        }
    }
    return -1;
}

uint32_t module_timestamp(uint8_t *module_address)
{
    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) module_address;
    if(image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    IMAGE_NT_HEADERS_CROSS *image_nt_headers = (IMAGE_NT_HEADERS_CROSS *)(
        module_address + image_dos_header->e_lfanew);
    if(image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return image_nt_headers->FileHeader.TimeDateStamp;
}

uint8_t *module_addr_timestamp(
    uint8_t *module_address, uint32_t module_size, funcoff_t *fo,
    uint32_t *cconv)
{
    (void) module_size;

    uint32_t timestamp = module_timestamp(module_address);

    for (; fo->timestamp != 0; fo++) {
        if(timestamp == fo->timestamp) {
            if(cconv != NULL) {
                *cconv = fo->cconv;
            }
            return module_address + fo->offset;
        }
    }

    log_action("gatherer");
    return NULL;
}

uint8_t *module_addr_timestamp_mod(
    uint8_t *module_address, uint32_t module_size,
    mod2funcoff_t *mf, const char *funcname, uint32_t *cconv
) {
    for (; mf->funcname != NULL; mf++) {
        if(strcmp(mf->funcname, funcname) == 0) {
            return module_addr_timestamp(
                module_address, module_size, mf->funcoff, cconv
            );
        }
    }
    return NULL;
}

insnoff_t *module_addr_timestamp2(uint8_t *module_address, insnoff_t *io)
{
    uint32_t timestamp = module_timestamp(module_address);

    for (; io->timestamp != 0; io++) {
        if(timestamp == io->timestamp) {
            return io;
        }
    }

    log_action("gatherer");
    return NULL;
}

insnoff_t *module_addr_timestamp_modinsn(
    uint8_t *module_address, uint32_t module_size,
    mod2insnoff_t *mi, const char *funcname
) {
    (void) module_size;

    for (; mi->funcname != NULL; mi++) {
        if(strcmp(mi->funcname, funcname) == 0) {
            return module_addr_timestamp2(module_address, mi->insnoff);
        }
    }
    return NULL;
}

int variant_to_bson(bson *b, const char *name, const VARIANT *v,
    void (*iunknown_callback)(bson *b, const char *name, IUnknown *unk))
{
    if(v == NULL) {
        return -1;
    }

    char buf[128];

    // Dereference an embedded VARIANT pointer.
    if(v->vt == (VT_VARIANT | VT_BYREF)) {
        v = v->pvarVal;
    }

    switch (v->vt) {
    case VT_EMPTY:
    case VT_NULL:
        bson_append_null(b, name);
        break;

    case VT_I2:
        bson_append_int(b, name, v->iVal);
        break;

    case VT_I4:
        bson_append_int(b, name, v->intVal);
        break;

    case VT_BSTR:
        log_wstring(b, name, v->bstrVal, sys_string_length(v->bstrVal));
        break;

    case VT_BSTR | VT_BYREF:
        log_wstring(b, name, *v->pbstrVal, sys_string_length(*v->pbstrVal));
        break;

    case VT_BOOL:
        bson_append_bool(b, name, v->boolVal != 0);
        break;

    case VT_DISPATCH:
        our_snprintf(buf, sizeof(buf), "<IDispatch @ 0x%x>", v->pdispVal);
        log_string(b, name, buf, strlen(buf));
        break;

    case VT_UNKNOWN:
        if(iunknown_callback != NULL) {
            iunknown_callback(b, name, v->punkVal);
        }
        else {
            our_snprintf(buf, sizeof(buf), "<IUnknown @ 0x%x>", v->punkVal);
            log_string(b, name, buf, strlen(buf));
        }
        break;

    default:
        our_snprintf(buf, sizeof(buf), "Unsupported vt=%d", v->vt);
        log_string(b, name, buf, strlen(buf));
        break;
    }

    return 0;
}

void iwbem_class_object_to_bson_helper(
    bson *b, const char *name, IUnknown *iunk)
{
    bson_append_start_object(b, name);
    iwbem_class_object_to_bson((IWbemClassObject *) iunk, b);
    bson_append_finish_object(b);
}

int iwbem_class_object_to_bson(IWbemClassObject *obj, bson *b)
{
    SAFEARRAY *argnames = NULL; HRESULT hr; VARIANT vt;
    BSTR name; char argname[MAX_PATH];

    hr = obj->lpVtbl->GetNames(
        obj, NULL, WBEM_FLAG_NONSYSTEM_ONLY, NULL, &argnames
    );

    if(SUCCEEDED(hr) == FALSE || argnames == NULL || argnames->cDims != 1 ||
            (argnames->fFeatures & FADF_BSTR) == 0) {
        return -1;
    }

    for (uint32_t idx = 0; idx < argnames->rgsabound[0].cElements; idx++) {
        name = ((BSTR *) argnames->pvData)[idx];
        hr = obj->lpVtbl->Get(obj, name, 0, &vt, NULL, NULL);
        if(SUCCEEDED(hr) != FALSE) {
            bstr_to_asciiz(name, argname, sizeof(argname));
            variant_to_bson(
                b, argname, &vt, &iwbem_class_object_to_bson_helper
            );
            variant_clear(&vt);
        }
    }
    safe_array_destroy(argnames);
    return 0;
}

void bstr_to_asciiz(const BSTR bstr, char *out, uint32_t length)
{
    const wchar_t *ptr = (const wchar_t *) bstr;

    length = MIN(sys_string_length(bstr), length-1);
    for (uint32_t idx = 0; idx < length; idx++) {
        *out++ = *ptr++;
    }

    *out = 0;
}

void hexdump(char *out, void *ptr, uint32_t length)
{
    uint8_t *p = (uint8_t *) ptr;
    while (length-- != 0) {
        out += our_snprintf(out, 10, "%x", *p++);
    }
    *out = 0;
}

uint32_t first_tid_from_pid(uint32_t process_identifier)
{
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        pipe("WARNING:Error getting snapshot handle to enumerate threads.");
        return 0;
    }

    THREADENTRY32 te; te.dwSize = sizeof(THREADENTRY32);
    if(Thread32First(snapshot_handle, &te) == FALSE) {
        pipe("WARNING:Error enumerating thread identifiers.");
        return 0;
    }

    uint32_t thread_identifier = 0;

    do {
        if(te.th32OwnerProcessID == process_identifier) {
            thread_identifier = te.th32ThreadID;
            break;
        }
    } while (Thread32Next(snapshot_handle, &te) != FALSE);

    CloseHandle(snapshot_handle);
    return thread_identifier;
}

int resume_thread_identifier(uint32_t thread_identifier)
{
    HANDLE thread_handle = open_thread(
        THREAD_SUSPEND_RESUME, thread_identifier
    );
    if(thread_handle != NULL) {
        resume_thread(thread_handle);
        close_handle(thread_handle);
        return 0;
    }
    return -1;
}

void logging_file_trigger(const wchar_t *filepath)
{
    if(g_monitor_logging == 0 && wcsicmp(filepath, g_monitor_trigger) == 0) {
        g_monitor_logging = 1;

        // Initialize extra exploit analysis functionality.
        if((g_monitor_mode & HOOK_MODE_EXPLOIT) == HOOK_MODE_EXPLOIT) {
            exploit_init();
        }
    }
}

#define BUFSZ 128

static void _search_helper(
    uint8_t *addr, int depth, int maxdepth, void *pattern, uint32_t length,
    uint32_t *stack, uint8_t *bufptr
) {
    uint8_t *buf = bufptr + depth * BUFSZ;

    if(copy_bytes(buf, addr, BUFSZ) < 0) {
        return;
    }

    for (uint32_t idx = 0; idx < BUFSZ - sizeof(uintptr_t); idx += 4) {
        if(idx + length < BUFSZ && memcmp(buf + idx, pattern, length) == 0) {
            stack[depth] = idx;

            uint8_t *ptr = bufptr + maxdepth * BUFSZ; char *hexptr = NULL;
            if(copy_bytes(ptr, buf + idx, BUFSZ) == 0) {
                hexptr = (char *) bufptr + maxdepth * BUFSZ + BUFSZ;
                hexdump(hexptr, ptr, BUFSZ - 1);
            }

            pipe(
                "DEBUG:pattern 0x%x 0x%x 0x%x 0x%x "
                "0x%x 0x%x 0x%x 0x%x addr=%p -> %z",
                stack[0], stack[1], stack[2], stack[3], stack[4],
                stack[5], stack[6], stack[7], addr + idx, hexptr
            );

            stack[depth] = 0;
        }
        else if(depth < maxdepth && *(uint8_t **)(buf + idx) != NULL) {
            stack[depth] = idx;
            _search_helper(
                *(uint8_t **)(buf + idx), depth + 1, maxdepth,
                pattern, length, stack, bufptr
            );
        }
    }
}

void search_deref(uint8_t *addr, int depth, void *pattern, uint32_t length)
{
    uint32_t stack[8]; uint8_t *buf = mem_alloc(BUFSZ * depth + BUFSZ * 3);

    // Maximum depth is 8, maximum pattern length is 32.
    depth = depth < 8 ? depth : 8;
    length = length < 32 ? length : 32;

    memset(stack, 0, sizeof(stack));
    _search_helper(addr, 0, depth, pattern, length, stack, buf);

    mem_free(buf);
}
