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

#ifndef MONITOR_MISC_H
#define MONITOR_MISC_H

#include <windows.h>
#include <wbemidl.h>
#include "bson.h"
#include "ntapi.h"

// TODO Enable Guard Page tracking when implemented correctly.
#define EXPLOIT_GUARD_SUPPORT_ENABLED 0

typedef void (*monitor_hook_t)(const char *library, void *module_handle);

int misc_init(const char *shutdown_mutex);
int misc_init2(monitor_hook_t monitor_hook, monitor_hook_t monitor_unhook);

// Call functions from monitor.c indirectly so that we don't have to include
// it by default when doing unittests.
void hook_library(const char *library, void *module_handle);
void unhook_library(const char *library, void *module_handle);

void misc_set_monitor_options(uint32_t track, uint32_t mode,
    const wchar_t *trigger);

wchar_t *get_unicode_buffer();
void free_unicode_buffer(wchar_t *ptr);

uint32_t pid_from_process_handle(HANDLE process_handle);
uint32_t pid_from_thread_handle(HANDLE thread_handle);
uint32_t tid_from_thread_handle(HANDLE thread_handle);
uint32_t parent_process_identifier();

uint32_t path_get_full_pathA(const char *in, wchar_t *out);
uint32_t path_get_full_pathW(const wchar_t *in, wchar_t *out);
uint32_t path_get_full_path_handle(HANDLE file_handle, wchar_t *out);
uint32_t path_get_full_path_unistr(const UNICODE_STRING *in, wchar_t *out);
uint32_t path_get_full_path_objattr(
    const OBJECT_ATTRIBUTES *in, wchar_t *out);

void wcsncpyA(wchar_t *dst, const char *src, uint32_t length);

void hide_module_from_peb(HMODULE module_handle);
const wchar_t *get_module_file_name(HMODULE module_handle);
void loaded_modules_enumerate(bson *b);
void destroy_pe_header(HANDLE module_handle);

wchar_t *extract_unicode_string_unistr(const UNICODE_STRING *unistr);
wchar_t *extract_unicode_string_objattr(const OBJECT_ATTRIBUTES *objattr);

uint32_t reg_get_key(HANDLE key_handle, wchar_t *regkey);
uint32_t reg_get_key_ascii(HANDLE key_handle,
    const char *subkey, uint32_t length, wchar_t *regkey);
uint32_t reg_get_key_asciiz(HANDLE key_handle,
    const char *subkey, wchar_t *regkey);
uint32_t reg_get_key_uni(HANDLE key_handle,
    const wchar_t *subkey, uint32_t length, wchar_t *regkey);
uint32_t reg_get_key_uniz(HANDLE key_handle,
    const wchar_t *subkey, wchar_t *regkey);
uint32_t reg_get_key_unistr(HANDLE key_handle,
    const UNICODE_STRING *unistr, wchar_t *regkey);
uint32_t reg_get_key_objattr(const OBJECT_ATTRIBUTES *obj, wchar_t *regkey);

void reg_get_info_from_keyvalue(const void *buf, uint32_t length,
    KEY_VALUE_INFORMATION_CLASS information_class, wchar_t **reg_name,
    uint32_t *reg_type, uint32_t *data_length, uint8_t **data);

const char *our_inet_ntoa(struct in_addr ipaddr);
uint16_t our_htons(uint16_t value);
uint32_t our_htonl(uint32_t value);

void get_ip_port(const struct sockaddr *addr, const char **ip, int *port);

int is_shutting_down();

void library_from_asciiz(const char *str, char *library, uint32_t length);
void library_from_unicodez(const wchar_t *str, char *library, int32_t length);
void library_from_unicode_string(const UNICODE_STRING *us,
    char *library, int32_t length);

int stacktrace(CONTEXT *ctx, uintptr_t *addrs, uint32_t length);

void *memdup(const void *addr, uint32_t length);
wchar_t *our_wcsdup(const wchar_t *s);
int page_is_readable(const void *addr);
int range_is_readable(const void *addr, uintptr_t size);
void clsid_to_string(REFCLSID rclsid, char *buf);

uint64_t hash_buffer(const void *buf, uint32_t length);
uint64_t hash_string(const char *buf, int32_t length);
uint64_t hash_stringW(const wchar_t *buf, int32_t length);
uint64_t hash_uint64(uint64_t value);

int ultostr(int64_t value, char *str, int base);

int our_vsnprintf(char *buf, int length, const char *fmt, va_list args);
int our_snprintf(char *buf, int length, const char *fmt, ...);
int our_memcmp(const void *a, const void *b, uint32_t length);
uint32_t our_strlen(const char *s);
void hexencode(char *dst, const uint8_t *src, uint32_t length);

const uint8_t *module_from_address(const uint8_t *addr);
uint32_t module_image_size(const uint8_t *addr);

void chtmtag_attrs(const void *chtmtag, bson *b);

void sha1(const void *buffer, uintptr_t buflen, char *hexdigest);

void int_or_strA(char **ptr, const char *str, char *numbuf);
void int_or_strW(wchar_t **ptr, const wchar_t *str, wchar_t *numbuf);

uint8_t *our_memmem(
    uint8_t *haystack, uint32_t haylength,
    const void *needle, uint32_t needlength,
    uint32_t *idx);
wchar_t *our_memmemW(
    const void *haystack, uint32_t haylength,
    const wchar_t *needle, uint32_t *idx);

uint32_t sys_string_length(const BSTR bstr);
BSTR sys_alloc_string_len(const OLECHAR *sz, UINT ui);
int sys_string_cmp(const BSTR bstr, const wchar_t *value);

HRESULT variant_change_type(
    VARIANTARG *dst, const VARIANTARG *src, USHORT flags, VARTYPE vt);
HRESULT variant_clear(VARIANTARG *arg);
HRESULT safe_array_destroy(SAFEARRAY *sa);

int is_exception_code_whitelisted(NTSTATUS exception_code);
int is_exception_address_whitelisted(uintptr_t addr);

typedef struct _funcoff_t {
    uint32_t timestamp;
    uint32_t offset;
    uint32_t cconv;
} funcoff_t;

typedef struct _mod2funcoff_t {
    const char *funcname;
    funcoff_t *funcoff;
} mod2funcoff_t;

typedef struct _insnoff_t {
    uint32_t timestamp;
    uint32_t offset;
    uint32_t signature;
    void (__stdcall *callback)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
} insnoff_t;

typedef struct _mod2insnoff_t {
    const char *funcname;
    insnoff_t *insnoff;
} mod2insnoff_t;

uint8_t *module_addr_timestamp(
    uint8_t *module_address, uint32_t module_size,
    funcoff_t *fo, uint32_t *cconv
);

uint8_t *module_addr_timestamp_mod(
    uint8_t *module_address, uint32_t module_size,
    mod2funcoff_t *mf, const char *funcname, uint32_t *cconv
);

insnoff_t *module_addr_timestamp_modinsn(
    uint8_t *module_address, uint32_t module_size,
    mod2insnoff_t *mi, const char *funcname
);

int variant_to_bson(bson *b, const char *name, const VARIANT *v,
    void (*iunknown_callback)(bson *b, const char *name, IUnknown *unk));
int iwbem_class_object_to_bson(IWbemClassObject *obj, bson *b);
void bstr_to_asciiz(const BSTR bstr, char *out, uint32_t length);
int vbe6_invoke_extract_args(uint8_t *addr, bson *b);

void vbe6_set_funcname(const wchar_t *funcname);
wchar_t *vbe6_get_funcname();

void hexdump(char *out, void *ptr, uint32_t length);
uint32_t first_tid_from_pid(uint32_t process_identifier);
int resume_thread_identifier(uint32_t thread_identifier);

void logging_file_trigger(const wchar_t *filepath);

// Searches for patterns in-memory while attempting to dereference any
// pointers found along the way. Useful during R&D.
void search_deref(uint8_t *addr, int depth, void *pattern, uint32_t length);

extern uint32_t g_extra_virtual_memory;

void set_processor_count(uint32_t processor_count);
void add_virtual_memory(uint64_t length);

void copy_init();
int copy_bytes(void *to, const void *from, uint32_t length);
int copy_unicodez(wchar_t *to, const wchar_t *from);
int copy_wcsncpyA(wchar_t *to, const char *from, uint32_t length);
uint32_t copy_strlen(const char *value);
uint32_t copy_strlenW(const wchar_t *value);
char *copy_utf8_string(const char *str, uint32_t length);
char *copy_utf8_wstring(const wchar_t *str, uint32_t length);
uint32_t copy_uint32(const void *value);
uint64_t copy_uint64(const void *value);
uintptr_t copy_uintptr(const void *value);
void *copy_ptr(const void *ptr);
void *deref(const void *ptr, uint32_t length);
uintptr_t derefi(uintptr_t ptr, uint32_t offset);
void copy_return();

void exploit_init();
int exploit_is_registered_guard_page(uintptr_t addr);
int WINAPI exploit_set_guard_page(void *addr);
int WINAPI exploit_unset_guard_page(void *addr);
void *exploit_get_last_guard_page();
void exploit_set_last_guard_page(void *addr);
int exploit_is_guard_page_referer_whitelisted(
    uintptr_t *addrs, uint32_t count);
int exploit_hotpatch_guard_page_referer(uintptr_t pc);

int exploit_is_stack_pivoted();
int exploit_makes_stack_executable(
    HANDLE process_handle, PVOID addr, DWORD new_protection);
int exploit_makes_heap_executable(
    HANDLE process_handle, PVOID addr, DWORD new_protection);
int exploit_insn_rewrite_to_lea(uint8_t *buf, uint8_t *insn);

#define OBJECT_NAME_INFORMATION_REQUIRED_SIZE \
    sizeof(OBJECT_NAME_INFORMATION) + sizeof(wchar_t) * MAX_PATH_W

#define PAGE_READABLE \
    (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | \
     PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | \
     PAGE_EXECUTE_WRITECOPY)

#define PAGE_EXECUTABLE \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | \
    PAGE_EXECUTE_WRITECOPY)

#if !__x86_64__

static inline uintptr_t get_ebp()
{
    uintptr_t ret;
    __asm__ volatile("movl %%ebp, %0" : "=r" (ret));
    return ret;
}

#endif

extern uint32_t g_monitor_track;
extern uint32_t g_monitor_mode;
extern int g_monitor_logging;

#define CONFIG_TRIGGER_NONE 0
#define CONFIG_TRIGGER_FILE 1

#endif
