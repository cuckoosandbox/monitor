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

// This program tests unicode filename support for the initial process.
// See also: https://github.com/cuckoobox/cuckoo/issues/502

/// FINISH= yes
/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <string.h>
#include <windows.h>
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

    wchar_t filename[MAX_PATH]; const wchar_t *ptr;
    GetModuleFileNameW(NULL, filename, MAX_PATH);

    ptr = wcsrchr(filename, '\\');
    if(ptr == NULL) {
        ptr = filename;
    }
    else {
        ptr++;
    }

#if __x86_64__
    assert(wcscmp(ptr, L"unicode-fname-\u202e-x64.exe") == 0);
#else
    assert(wcscmp(ptr, L"unicode-fname-\u202e-x86.exe") == 0);
#endif

    pipe("DEBUG:Filename -> %Z", ptr);
    pipe("INFO:Test finished!");
    return 0;
}
