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

void *mem_alloc(uint32_t length)
{
    void *ptr = virtual_alloc(NULL, length + sizeof(uint32_t),
        MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if(ptr == NULL) {
        return NULL;
    }

    memset(ptr, 0, length + sizeof(uint32_t));

    *(uint32_t *) ptr = length;
    return (uint32_t *) ptr + 1;
}

void *mem_realloc(void *ptr, uint32_t length)
{
    void *newptr = mem_alloc(length);
    if(newptr == NULL) {
        return NULL;
    }

    if(ptr != NULL) {
        uint32_t oldlength = *((uint32_t *) ptr - 1);
        memcpy(newptr, ptr, min(length, oldlength));
        mem_free(ptr);
    }
    return newptr;
}

void mem_free(void *ptr)
{
    if(ptr != NULL) {
        uint32_t oldlength = *((uint32_t *) ptr - 1);
        virtual_free((uint32_t *) ptr - 1,
            oldlength + sizeof(uint32_t), MEM_RELEASE);
    }
}

void array_init(array_t *array)
{
    array->length = 0;
    array->elements = NULL;
    InitializeCriticalSection(&array->cs);
}

static int _array_ensure(array_t *array, uint32_t index)
{
    if(array->elements == NULL || index >= array->length) {
        array->elements = (void **)
            mem_realloc(array->elements, (index + 1) * sizeof(void *));
        if(array->elements == NULL) {
            return -1;
        }

        array->length = index + 1;
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
    return array_set(array, index, NULL);
}
