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

int native_init();

int virtual_query_ex(HANDLE process_handle, void *addr,
    MEMORY_BASIC_INFORMATION *mbi);

int virtual_query(void *addr, MEMORY_BASIC_INFORMATION *mbi);

void *virtual_alloc_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t allocation_type, uint32_t protection);

void *virtual_alloc(void *addr, uintptr_t size,
    uint32_t allocation_type, uint32_t protection);

int virtual_protect_ex(HANDLE process_handle, void *addr,
    uintptr_t size, uint32_t protection);

int virtual_protect(void *addr, uintptr_t size, uint32_t protection);

#endif
