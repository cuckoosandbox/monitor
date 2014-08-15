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

#ifndef MONITOR_MISC_H
#define MONITOR_MISC_H

#include <windows.h>
#include "ntapi.h"

void misc_init();

uintptr_t pid_from_process_handle(HANDLE process_handle);
uintptr_t pid_from_thread_handle(HANDLE thread_handle);
uintptr_t parent_process_id();

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);
uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len);
uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length);
int ensure_absolute_path(wchar_t *out, const wchar_t *in, int length);

void wcsncpyA(wchar_t *str, const char *value, uint32_t length);

void hide_module_from_peb(HMODULE module_handle);
void destroy_pe_header(HANDLE module_handle);

uint32_t reg_get_key(HANDLE key_handle, wchar_t *regkey, uint32_t length);
uint32_t reg_get_key_objattr(const OBJECT_ATTRIBUTES *obj,
    wchar_t *regkey, uint32_t length);

void get_ip_port(const struct sockaddr *addr, const char **ip, int *port);

int is_shutting_down();

void library_from_unicode_string(const UNICODE_STRING *us,
    char *library, int32_t length);

void setup_exception_handler();

#define COPY_UNICODE_STRING(local_name, param_name) \
    UNICODE_STRING local_name; wchar_t local_name##_buf[MAX_PATH+128]; \
    local_name.Length = local_name.MaximumLength = 0; \
    local_name.Buffer = local_name##_buf; \
    memset(local_name##_buf, 0, sizeof(local_name##_buf)); \
    if(param_name != NULL && \
            param_name->MaximumLength < sizeof(local_name##_buf)) { \
        local_name.Length = param_name->Length; \
        local_name.MaximumLength = param_name->MaximumLength; \
        memcpy(local_name.Buffer, param_name->Buffer, \
            local_name.MaximumLength); \
    }

#define COPY_OBJECT_ATTRIBUTES(local_name, param_name) \
    OBJECT_ATTRIBUTES local_name; \
    memset(&local_name, 0, sizeof(local_name)); \
    COPY_UNICODE_STRING(local_name##_str, unistr_from_objattr(param_name)); \
    if(param_name != NULL) { \
        memcpy(&local_name, param_name, sizeof(local_name)); \
        local_name.ObjectName = &local_name##_str; \
    }

#define FILE_NAME_INFORMATION_REQUIRED_SIZE \
    sizeof(FILE_NAME_INFORMATION) + sizeof(wchar_t) * MAX_PATH

#endif
