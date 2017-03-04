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

// This program tests some functionality of our divide-and-conquer
// implementation.

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

    dnq_t d1, d2, d3;

    uint32_t val1[] = {
        1, 6, 4, 8, 13337, 42, 89, 9001, 90,
    };
    uint32_t val1_sorted[] = {
        1, 4, 6, 8, 42, 89, 90, 9001, 13337,
    };

    dnq_init(&d1, val1, sizeof(uint32_t), sizeof(val1) / sizeof(uint32_t));
    assert(memcmp(d1.list, val1_sorted, sizeof(val1_sorted)) == 0);
    assert(dnq_has32(&d1, 4) == 1);
    assert(dnq_has32(&d1, 0) == 0);
    assert(dnq_has32(&d1, 1) == 1);
    assert(dnq_has32(&d1, 2) == 0);
    assert(dnq_has32(&d1, 43) == 0);
    assert(dnq_has32(&d1, 91) == 0);
    assert(dnq_has32(&d1, 90) == 1);
    assert(dnq_has32(&d1, 9002) == 0);
    assert(dnq_has32(&d1, 9000) == 0);
    assert(dnq_has32(&d1, 13337) == 1);
    assert(dnq_has32(&d1, 13338) == 0);
    assert(dnq_has32(&d1, 13336) == 0);
    assert(dnq_has32(&d1, 88) == 0);
    assert(dnq_has32(&d1, 41) == 0);
    assert(dnq_has32(&d1, 42) == 1);

    uint64_t val2[] = {
        1, 6, 4, 8, 13337, 42, 89, 9001, 90,
    };
    uint64_t val2_sorted[] = {
        1, 4, 6, 8, 42, 89, 90, 9001, 13337,
    };

    dnq_init(&d2, val2, sizeof(uint64_t), sizeof(val2) / sizeof(uint64_t));
    assert(memcmp(d2.list, val2_sorted, sizeof(val2_sorted)) == 0);
    assert(dnq_has64(&d2, 4) == 1);
    assert(dnq_has64(&d2, 0) == 0);
    assert(dnq_has64(&d2, 1) == 1);
    assert(dnq_has64(&d2, 2) == 0);
    assert(dnq_has64(&d2, 43) == 0);
    assert(dnq_has64(&d2, 91) == 0);
    assert(dnq_has64(&d2, 90) == 1);
    assert(dnq_has64(&d2, 9002) == 0);
    assert(dnq_has64(&d2, 9000) == 0);
    assert(dnq_has64(&d2, 13337) == 1);
    assert(dnq_has64(&d2, 13338) == 0);
    assert(dnq_has64(&d2, 13336) == 0);
    assert(dnq_has64(&d2, 88) == 0);
    assert(dnq_has64(&d2, 41) == 0);
    assert(dnq_has64(&d2, 42) == 1);

    uintptr_t val3[] = {
        1, 6, 4, 8, 13337, 42, 89, 9001, 90,
    };
    uintptr_t val3_sorted[] = {
        1, 4, 6, 8, 42, 89, 90, 9001, 13337,
    };

    dnq_init(&d3, val3, sizeof(uintptr_t), sizeof(val3) / sizeof(uintptr_t));
    assert(memcmp(d3.list, val3_sorted, sizeof(val3_sorted)) == 0);
    assert(dnq_hasptr(&d3, 4) == 1);
    assert(dnq_hasptr(&d3, 0) == 0);
    assert(dnq_hasptr(&d3, 1) == 1);
    assert(dnq_hasptr(&d3, 2) == 0);
    assert(dnq_hasptr(&d3, 43) == 0);
    assert(dnq_hasptr(&d3, 91) == 0);
    assert(dnq_hasptr(&d3, 90) == 1);
    assert(dnq_hasptr(&d3, 9002) == 0);
    assert(dnq_hasptr(&d3, 9000) == 0);
    assert(dnq_hasptr(&d3, 13337) == 1);
    assert(dnq_hasptr(&d3, 13338) == 0);
    assert(dnq_hasptr(&d3, 13336) == 0);
    assert(dnq_hasptr(&d3, 88) == 0);
    assert(dnq_hasptr(&d3, 41) == 0);
    assert(dnq_hasptr(&d3, 42) == 1);

    assert(dnq_iter32(&d1)[4] == 42);
    assert(dnq_iter64(&d2)[4] == 42);
    assert(dnq_iterptr(&d3)[4] == 42);
    pipe("INFO:Test finished!");
    return 0;
}
