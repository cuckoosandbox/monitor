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

// Due to integer size issues in 64-bit DLLs we're going to check bitsize of
// various data types so to help us decide which logging data type to use.

/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

#if __x86_64__
#define PTR_SIZE 8
#else
#define PTR_SIZE 4
#endif

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    assert(sizeof(int) == 4);
    assert(sizeof(long) == 4);
    assert(sizeof(LONG) == 4);
    assert(sizeof(u_long) == 4);
    assert(sizeof(ULONG) == 4);
    assert(sizeof(BOOL) == 4);
    assert(sizeof(BOOLEAN) == 1);
    assert(sizeof(DWORD) == 4);
    assert(sizeof(UINT) == 4);

    assert(sizeof(LARGE_INTEGER) == 8);

    assert(sizeof(uintptr_t) == PTR_SIZE);
    assert(sizeof(ULONG_PTR) == PTR_SIZE);
    assert(sizeof(DWORD_PTR) == PTR_SIZE);
    assert(sizeof(SIZE_T) == PTR_SIZE);
    assert(sizeof(HANDLE) == PTR_SIZE);
    pipe("INFO:Test finished!");
    return 0;
}
