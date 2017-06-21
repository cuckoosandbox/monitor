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
#include "ntapi.h"

typedef struct _last_error_t {
    uint32_t nt_status;
    uint32_t lasterror;
} last_error_t;

#if __x86_64__
#define MEMORY_BASIC_INFORMATION_CROSS MEMORY_BASIC_INFORMATION64
#else
#define MEMORY_BASIC_INFORMATION_CROSS MEMORY_BASIC_INFORMATION
#endif

int native_init();

int virtual_query_ex(HANDLE process_handle, const void *addr,
    MEMORY_BASIC_INFORMATION_CROSS *mbi);

int virtual_query(const void *addr, MEMORY_BASIC_INFORMATION_CROSS *mbi);

void *virtual_alloc_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t allocation_type, uint32_t protection);

void *virtual_alloc(void *addr, uintptr_t size,
    uint32_t allocation_type, uint32_t protection);

void *virtual_alloc_rw(void *addr, uintptr_t size);

int virtual_free_ex(HANDLE process_handle, const void *addr, uintptr_t size,
    uint32_t free_type);

int virtual_free(const void *addr, uintptr_t size, uint32_t free_type);

NTSTATUS virtual_protect_ex(HANDLE process_handle, const void *addr,
    uintptr_t size, uint32_t protection);

NTSTATUS virtual_protect(const void *addr, uintptr_t size,
    uint32_t protection);

uint32_t query_information_process(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length);

uint32_t query_information_thread(HANDLE process_handle,
    uint32_t information_class, void *buf, uint32_t length);

NTSTATUS virtual_read_ex(HANDLE process_handle, void *addr,
    void *buffer, uintptr_t *size);
NTSTATUS virtual_read(void *addr, void *buffer, uintptr_t *size);

uint32_t query_object(HANDLE handle, uint32_t information_class,
    void *buf, uint32_t length);

uint32_t query_key(HANDLE key_handle, uint32_t information_class,
    void *buf, uint32_t length);

int duplicate_handle(HANDLE source_process_handle, HANDLE source_handle,
    HANDLE target_process_handle, HANDLE *target_handle,
    uint32_t desired_access, int inherit_handle, uint32_t options);

NTSTATUS write_file(HANDLE file_handle, const void *buffer, uint32_t length,
    uint32_t *bytes_written);

NTSTATUS transact_named_pipe(HANDLE pipe_handle,
    const void *inbuf, uintptr_t inbufsz, void *outbuf, uintptr_t outbufsz,
    uintptr_t *written);

NTSTATUS set_named_pipe_handle_mode(HANDLE pipe_handle, uint32_t mode);

int close_handle(HANDLE object_handle);

void sleep(uint32_t milliseconds);
uint32_t get_tick_count();

void register_dll_notification(LDR_DLL_NOTIFICATION_FUNCTION fn, void *param);

void get_last_error(last_error_t *error);
void set_last_error(last_error_t *error);

HANDLE get_current_process();
uint32_t get_current_process_id();
HANDLE get_current_thread();
uint32_t get_current_thread_id();

uint32_t get_window_thread_process_id(HWND hwnd, uint32_t *pid);
int message_box(HWND hwnd, const char *body, const char *title, int flags);

HANDLE open_thread(uint32_t desired_mask, uint32_t thread_identifier);
uint32_t resume_thread(HANDLE thread_handle);

int set_std_handle(DWORD std_handle, HANDLE file_handle);
int is_std_handle(HANDLE file_handle);

#endif
