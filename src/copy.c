/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2016-2018 Cuckoo Foundation.

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

#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <windows.h>
#include "log.h"
#include "memory.h"
#include "misc.h"
#include "utf8.h"

typedef struct _tls_copy_t {
    jmp_buf jb;
    int active;
} tls_copy_t;

static uint32_t g_tls_index;

void copy_init()
{
    g_tls_index = TlsAlloc();
}

tls_copy_t *copy_get_tls()
{
    tls_copy_t *ret = (tls_copy_t *) TlsGetValue(g_tls_index);
    if(ret == NULL) {
        ret = (tls_copy_t *) mem_alloc_aligned(sizeof(tls_copy_t));
        TlsSetValue(g_tls_index, ret);
    }
    return ret;
}

int copy_bytes(void *to, const void *from, uint32_t length)
{
    uint8_t *to_ = (uint8_t *) to, *from_ = (uint8_t *) from;
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        while (length-- != 0) {
            *to_++ = *from_++;
        }
        tls->active = 0;
        return 0;
    }
    tls->active = 0;
    return -1;
}

int copy_unicodez(wchar_t *to, const wchar_t *from)
{
    uint32_t length = MAX_PATH_W;
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        while (length-- != 0 && (*to++ = *from++) != 0);
        *to = 0;
        tls->active = 0;
        return 0;
    }
    tls->active = 0;
    return -1;
}

int copy_wcsncpyA(wchar_t *to, const char *from, uint32_t length)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        wcsncpyA(to, from, length);
        tls->active = 0;
        return 0;
    }
    tls->active = 0;
    return -1;
}

uint32_t copy_strlen(const char *value)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        for (uint32_t idx = 0; ; idx++) {
            if(*value++ == 0) {
                tls->active = 0;
                return idx;
            }
        }
    }
    tls->active = 0;
    return 0;
}

uint32_t copy_strlenW(const wchar_t *value)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        for (uint32_t idx = 0; ; idx++) {
            if(*value++ == 0) {
                tls->active = 0;
                return idx;
            }
        }
    }
    tls->active = 0;
    return 0;
}

char *copy_utf8_string(const char *str, uint32_t length)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        char *ret = utf8_string(str, length);
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return NULL;
}

char *copy_utf8_wstring(const wchar_t *str, uint32_t length)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        char *ret = utf8_wstring(str, length);
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return NULL;
}

uint32_t copy_uint32(const void *value)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        uint32_t ret = *(uint32_t *) value;
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return 0;
}

uint64_t copy_uint64(const void *value)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        uint64_t ret = *(uint64_t *) value;
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return 0;
}

uintptr_t copy_uintptr(const void *value)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        uintptr_t ret = *(uintptr_t *) value;
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return 0;
}

void *copy_ptr(const void *ptr)
{
    tls_copy_t *tls = copy_get_tls();

    tls->active = 1;
    if(setjmp(tls->jb) == 0) {
        void *ret = *(void **) ptr;
        tls->active = 0;
        return ret;
    }
    tls->active = 0;
    return NULL;
}

void *deref(const void *ptr, uint32_t offset)
{
    if(ptr == NULL) {
        return NULL;
    }
    return copy_ptr((const uint8_t *) ptr + offset);
}

uintptr_t derefi(uintptr_t ptr, uint32_t offset)
{
    return (uintptr_t) deref((void *) ptr, offset);
}

void copy_return()
{
    tls_copy_t *tls = copy_get_tls();

    if(tls->active != 0) {
        longjmp(tls->jb, 1);
    }
}
