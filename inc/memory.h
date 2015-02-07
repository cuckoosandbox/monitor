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

#ifndef MONITOR_MEMORY_H
#define MONITOR_MEMORY_H

#include <stdint.h>
#include <windows.h>

typedef struct _array_t {
    uint32_t length;
    void   **elements;
    CRITICAL_SECTION cs;
} array_t;

uintptr_t roundup2(uintptr_t value);
uintptr_t mem_suggested_size(uintptr_t size);

void *mem_alloc(uint32_t length);
void *mem_realloc(void *ptr, uint32_t length);
void mem_free(void *ptr);

void array_init(array_t *array);
int array_set(array_t *array, uintptr_t index, void *value);
void *array_get(array_t *array, uintptr_t index);
void array_unset(array_t *array, uintptr_t index);

#endif
