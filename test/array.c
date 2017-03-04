/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2015-2017 Cuckoo Foundation.

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

// This program tests some functionality of our array implementation.

/// FINISH= yes
/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "hooking.h"
#include "memory.h"
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
    mem_init();
    assert(native_init() == 0);

    array_t arr;
    array_init(&arr);

    assert(array_set(&arr, 0, "hoi0") == 0);
    assert(array_set(&arr, 1, "hoi1") == 0);
    assert(array_set(&arr, 2, "hoi2") == 0);
    assert(array_set(&arr, 3, "hoi3") == 0);

    assert(strcmp(array_get(&arr, 2), "hoi2") == 0);
    assert(strcmp(array_get(&arr, 3), "hoi3") == 0);
    assert(array_get(&arr, 0x4000) == NULL);

    assert(array_unset(&arr, 2) == 0);
    assert(array_unset(&arr, 0x4001) == -1);
    assert(array_get(&arr, 2) == NULL);
    assert(strcmp(array_get(&arr, 1), "hoi1") == 0);
    assert(array_unset(&arr, 2) == 0);
    pipe("INFO:Test finished!");
    return 0;
}
