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

/// FINISH= yes
/// FREE=yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include "config.h"
#include "hooking.h"
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

    assert(GetCurrentProcessId() == get_current_process_id());
    assert(GetCurrentThreadId() == get_current_thread_id());

    assert(pid_from_process_handle(get_current_process()) == get_current_process_id());
    assert(pid_from_thread_handle(get_current_thread()) == get_current_process_id());
    assert(tid_from_thread_handle(get_current_thread()) == get_current_thread_id());

    last_error_t err;
    assert((SetLastError(42), get_last_error(&err), err.lasterror == 42));
    assert((SetLastError(0), set_last_error(&err), GetLastError() == 42));
    pipe("INFO:Test finished!");
    return 0;
}
