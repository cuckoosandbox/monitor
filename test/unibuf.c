/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2017 Cuckoo Foundation.

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

// Tests the unicode buffer functionality.

/// FINISH= yes
/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    hook_init(GetModuleHandle(NULL));
    assert(native_init() == 0);
    misc_init("hoi");

    wchar_t *a, *b, *c, *d;

    assert((a = get_unicode_buffer()) != NULL);
    assert((b = get_unicode_buffer()) != NULL);
    assert((c = get_unicode_buffer()) != NULL);

    memset(b, 0x01, 32);
    free_unicode_buffer(b);

    // The first utf16 character is zeroed.
    assert((b = get_unicode_buffer()) != NULL && memcmp(b, "\x00\x00\x01\x01\x01\x01", 6) == 0);

    assert((d = get_unicode_buffer()) != NULL);

    // The first available pointer is always used when possible.
    free_unicode_buffer(a); free_unicode_buffer(c);
    assert(get_unicode_buffer() == a && get_unicode_buffer() == c);

    uint32_t bufcount = 0x1000/sizeof(void *) + 4;

    // Allocate X pointers and then free them. The last N pointers will
    // not be managed by the custom memory manager. TODO Could improve these
    // checks to show that memory is actually being allocated & deallocated.
    static wchar_t *ptrs[0x1000];
    for (uint32_t idx = 0; idx < bufcount; idx++) {
        ptrs[idx] = get_unicode_buffer();
    }

    for (uint32_t idx = 0; idx < bufcount; idx++) {
        free_unicode_buffer(ptrs[idx]);
    }
    pipe("INFO:Test finished!");
    return 0;
}
