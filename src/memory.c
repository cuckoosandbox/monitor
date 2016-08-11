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
#include <windows.h>
#include "memory.h"
#include "native.h"
#include "pipe.h"

static SYSTEM_INFO g_si;

uintptr_t roundup2(uintptr_t value)
{
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
#if __x86_64__
    value |= value >> 32;
#endif
    return ++value;
}

uintptr_t mem_suggested_size(uintptr_t size)
{
    size = roundup2(size);

    // Go for at least one page.
    if(size < g_si.dwPageSize) {
        size = g_si.dwPageSize;
    }

    return size - sizeof(uintptr_t);
}

void mem_init()
{
    GetSystemInfo(&g_si);
}

void *mem_alloc(uint32_t length)
{
    if(length == 0) {
        return NULL;
    }

    uint32_t real_length = length + sizeof(uintptr_t);

#if DEBUG_HEAPCORRUPTION
    real_length = (real_length + 0x1fff) / 0x1000 * 0x1000;
#endif

    void *ptr = virtual_alloc(NULL, real_length,
        MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if(ptr == NULL) {
        return NULL;
    }

#if DEBUG_HEAPCORRUPTION
    // gflags.exe-like heap corruption functionality.
    virtual_protect(ptr + real_length - 0x1000, 0x1000, PAGE_READONLY);
    ptr += real_length - 0x1000 - length - sizeof(uintptr_t);
#endif

    memset(ptr, 0, length + sizeof(uintptr_t));

    *(uintptr_t *) ptr = length;
    return (uintptr_t *) ptr + 1;
}

void *mem_realloc(void *ptr, uint32_t length)
{
    void *newptr = mem_alloc(length);
    if(newptr == NULL) {
        return NULL;
    }

    if(ptr != NULL) {
        uintptr_t oldlength = *((uintptr_t *) ptr - 1);
        memcpy(newptr, ptr, min(length, oldlength));
        mem_free(ptr);
    }
    return newptr;
}

void mem_free(void *ptr)
{
    if(ptr != NULL) {
        uintptr_t oldlength = *((uintptr_t *) ptr - 1);
        virtual_free((uintptr_t *) ptr - 1,
            oldlength + sizeof(uintptr_t), MEM_RELEASE);
    }
}

void array_init(array_t *array)
{
    array->length = 0;
    array->elements = NULL;
    InitializeCriticalSection(&array->cs);
}

static uintptr_t _suggested_array_length(uintptr_t length)
{
    return mem_suggested_size(length * sizeof(void *)) / sizeof(void *);
}

static int _array_ensure(array_t *array, uint32_t index)
{
    if(array->elements == NULL || index >= array->length) {
        uintptr_t newlength = _suggested_array_length(index + 1);

        array->elements = (void **)
            mem_realloc(array->elements, newlength * sizeof(void *));
        if(array->elements == NULL) {
            return -1;
        }

        array->length = newlength;
    }
    return 0;
}

int array_set(array_t *array, uintptr_t index, void *value)
{
    EnterCriticalSection(&array->cs);

    if(_array_ensure(array, index) < 0) {
        LeaveCriticalSection(&array->cs);
        return -1;
    }

    array->elements[index] = value;

    LeaveCriticalSection(&array->cs);
    return 0;
}

void *array_get(array_t *array, uintptr_t index)
{
    EnterCriticalSection(&array->cs);

    void *ret = NULL;
    if(index < array->length) {
        ret = array->elements[index];
    }

    LeaveCriticalSection(&array->cs);
    return ret;
}

int array_unset(array_t *array, uintptr_t index)
{
    EnterCriticalSection(&array->cs);

    int ret = -1;
    if(index < array->length) {
        array->elements[index] = NULL;
        ret = 0;
    }

    LeaveCriticalSection(&array->cs);
    return ret;
}

static int _slab_ensure(slab_t *slab)
{
    if(slab->offset == slab->length) {
        uint8_t *mem = virtual_alloc(NULL, slab->size * slab->count,
            MEM_COMMIT | MEM_RESERVE, slab->memprot);
        if(mem == NULL) {
            pipe("CRITICAL:Error allocating memory for slab!");
            return -1;
        }

        array_set(&slab->array, slab->offset / slab->count, mem);

        slab->length += slab->count;
    }
    return 0;
}

void slab_init(slab_t *slab, uint32_t size, uint32_t count,
    uint32_t memory_protection)
{
    array_init(&slab->array);
    slab->size = size;
    slab->count = count;
    slab->offset = 0;
    slab->length = 0;
    slab->memprot = memory_protection;
}

void *slab_getmem(slab_t *slab)
{
    if(_slab_ensure(slab) == 0) {
        uint8_t *mem = array_get(&slab->array, slab->offset / slab->count);
        uint8_t *ret = mem + slab->size * (slab->offset % slab->count);
        slab->offset++;
        return ret;
    }
    return NULL;
}

void slab_return_last(slab_t *slab)
{
    if(slab->offset != 0) {
        slab->offset--;
    }
}

uint32_t slab_size(const slab_t *slab)
{
    return slab->size;
}

static int _sort_uint32(const void *a, const void *b)
{
    uint32_t _a = *(const uint32_t *) a;
    uint32_t _b = *(const uint32_t *) b;
    return _a - _b;
}

static int _sort_uint64(const void *a, const void *b)
{
    uint64_t _a = *(const uint64_t *) a;
    uint64_t _b = *(const uint64_t *) b;
    return _a - _b;
}

int dnq_init(dnq_t *dnq, void *list, uint32_t size, uint32_t length)
{
    dnq->list = list;
    dnq->size = size;
    dnq->length = length;

    switch (size) {
    case sizeof(uint32_t):
        qsort(list, length, size, &_sort_uint32);
        break;

    case sizeof(uint64_t):
        qsort(list, length, size, &_sort_uint64);
        break;
    }

    return 0;
}

uint32_t *dnq_iter32(dnq_t *dnq)
{
    return (uint32_t *) dnq->list;
}

uint64_t *dnq_iter64(dnq_t *dnq)
{
    return (uint64_t *) dnq->list;
}

uintptr_t *dnq_iterptr(dnq_t *dnq)
{
    return (uintptr_t *) dnq->list;
}

int dnq_isempty(dnq_t *dnq)
{
    return dnq->list == NULL || dnq->length == 0;
}

int dnq_has32(dnq_t *dnq, uint32_t value)
{
    uint32_t low = 0, high = dnq->length - 1;
    uint32_t *list = dnq_iter32(dnq);

    while (high - low > 1) {
        uint32_t index = low + (high - low) / 2;
        if(value == list[index]) {
            return 1;
        }

        if(value > list[index]) {
            low = index;
            continue;
        }

        if(value < list[index]) {
            high = index;
            continue;
        }
    }

    if(value == list[low] || value == list[high]) {
        return 1;
    }

    return 0;
}

int dnq_has64(dnq_t *dnq, uint64_t value)
{
    uint32_t low = 0, high = dnq->length - 1;
    uint64_t *list = dnq_iter64(dnq);

    while (high - low > 1) {
        uint32_t index = low + (high - low) / 2;
        if(value == list[index]) {
            return 1;
        }

        if(value > list[index]) {
            low = index;
            continue;
        }

        if(value < list[index]) {
            high = index;
            continue;
        }
    }

    if(value == list[low] || value == list[high]) {
        return 1;
    }

    return 0;
}

int dnq_hasptr(dnq_t *dnq, uintptr_t value)
{
    switch (sizeof(uintptr_t)) {
    case sizeof(uint32_t):
        return dnq_has32(dnq, value);

    case sizeof(uint64_t):
        return dnq_has64(dnq, value);
    }
}
