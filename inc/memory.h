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

typedef struct _slab_t {
    array_t array;
    uint32_t size;
    uint32_t count;

    uint32_t offset;
    uint32_t length;
    uint32_t memprot;
} slab_t;

uintptr_t roundup2(uintptr_t value);
uintptr_t mem_suggested_size(uintptr_t size);

void mem_init();
void *mem_alloc(uint32_t length);
void *mem_realloc(void *ptr, uint32_t length);
void mem_free(void *ptr);

void array_init(array_t *array);
int array_set(array_t *array, uintptr_t index, void *value);
void *array_get(array_t *array, uintptr_t index);
int array_unset(array_t *array, uintptr_t index);

static inline int array_seti(array_t *array, uintptr_t index, uintptr_t value)
{
    return array_set(array, index, (void *) value);
}

static inline uintptr_t array_geti(array_t *array, uintptr_t index)
{
    return (uintptr_t) array_get(array, index);
}

void slab_init(slab_t *slab, uint32_t size, uint32_t count,
    uint32_t memory_protection);
void *slab_getmem(slab_t *slab);
void slab_return_last(slab_t *slab);
uint32_t slab_size(const slab_t *slab);

typedef struct _dnq_t {
    void *list;
    uint32_t size;
    uint32_t length;
} dnq_t;

int dnq_init(dnq_t *dnq, void *list, uint32_t size, uint32_t length);
uint32_t *dnq_iter32(dnq_t *dnq);
uint64_t *dnq_iter64(dnq_t *dnq);
uintptr_t *dnq_iterptr(dnq_t *dnq);
int dnq_isempty(dnq_t *dnq);
int dnq_has32(dnq_t *dnq, uint32_t value);
int dnq_has64(dnq_t *dnq, uint64_t value);
int dnq_hasptr(dnq_t *dnq, uintptr_t value);

#endif
