/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2016 Cuckoo Foundation.

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
#include "misc.h"
#include "utf8.h"

static __thread jmp_buf _jb;

int copy_bytes(void *to, const void *from, uint32_t length)
{
    uint8_t *to_ = (uint8_t *) to, *from_ = (uint8_t *) from;

    if(setjmp(_jb) == 0) {
        while (length-- != 0) {
            *to_++ = *from_++;
        }
        return 0;
    }
    return -1;
}

int copy_unicodez(wchar_t *to, const wchar_t *from)
{
    uint32_t length = MAX_PATH_W;
    if(setjmp(_jb) == 0) {
        while (length-- != 0 && (*to++ = *from++) != 0);
        *to = 0;
        return 0;
    }
    return -1;
}

int copy_wcsncpyA(wchar_t *to, const char *from, uint32_t length)
{
    if(setjmp(_jb) == 0) {
        wcsncpyA(to, from, length);
        return 0;
    }
    return -1;
}

uint32_t copy_strlen(const char *value)
{
    if(setjmp(_jb) == 0) {
        for (uint32_t idx = 0; ; idx++) {
            if(*value++ == 0) {
                return idx;
            }
        }
    }
    return 0;
}

uint32_t copy_strlenW(const wchar_t *value)
{
    if(setjmp(_jb) == 0) {
        for (uint32_t idx = 0; ; idx++) {
            if(*value++ == 0) {
                return idx;
            }
        }
    }
    return 0;
}

char *copy_utf8_string(const char *str, uint32_t length)
{
    if(setjmp(_jb) == 0) {
        return utf8_string(str, length);
    }
    return NULL;
}

char *copy_utf8_wstring(const wchar_t *str, uint32_t length)
{
    if(setjmp(_jb) == 0) {
        return utf8_wstring(str, length);
    }
    return NULL;
}

uint32_t copy_uint32(const void *value)
{
    if(setjmp(_jb) == 0) {
        return *(uint32_t *) value;
    }
    return 0;
}

uint64_t copy_uint64(const void *value)
{
    if(setjmp(_jb) == 0) {
        return *(uint64_t *) value;
    }
    return 0;
}

void *copy_ptr(const void *ptr)
{
    if(setjmp(_jb) == 0) {
        return *(void **) ptr;
    }
    return NULL;
}

void copy_return()
{
    longjmp(_jb, 1);
}
