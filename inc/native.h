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

#ifndef MONITOR_NATIVE_H
#define MONITOR_NATIVE_H

#include <stdint.h>
#include <windows.h>

typedef struct _last_error_t {
    uint32_t nt_status;
    uint32_t lasterror;
} last_error_t;

int native_init();

int virtual_query_ex(HANDLE process_handle, const void *addr,
    MEMORY_BASIC_INFORMATION *mbi);

int virtual_query(const void *addr, MEMORY_BASIC_INFORMATION *mbi);

void *virtual_alloc_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t allocation_type, uint32_t protection);

void *virtual_alloc(void *addr, uintptr_t size,
    uint32_t allocation_type, uint32_t protection);

int virtual_free_ex(HANDLE process_handle, const void *addr, uintptr_t size,
    uint32_t free_type);

int virtual_free(const void *addr, uintptr_t size, uint32_t free_type);

int virtual_protect_ex(HANDLE process_handle, const void *addr,
    uintptr_t size, uint32_t protection);

int virtual_protect(const void *addr, uintptr_t size, uint32_t protection);

uint32_t query_information_process(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length);

uint32_t query_information_thread(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length);

uint32_t query_object(HANDLE handle, uint32_t information_class,
    void *buf, uint32_t length);

uint32_t query_key(HANDLE key_handle, uint32_t information_class,
    void *buf, uint32_t length);

int duplicate_handle(HANDLE source_process_handle, HANDLE source_handle,
    HANDLE target_process_handle, HANDLE *target_handle,
    uint32_t desired_access, int inherit_handle, uint32_t options);

int close_handle(HANDLE object_handle);

void get_last_error(last_error_t *error);
void set_last_error(last_error_t *error);

HANDLE get_current_process();
uintptr_t get_current_process_id();
HANDLE get_current_thread();
uintptr_t get_current_thread_id();

#endif
