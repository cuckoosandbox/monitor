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

#ifndef MONITOR_HOOKING_H
#define MONITOR_HOOKING_H

#include <stdint.h>
#include <windows.h>
#include "monitor.h"

#define RETADDRCNT 64

typedef struct _hook_t {
    // Library and function name.
    const char *library;
    const char *funcname;

    // Hook handler.
    FARPROC handler;

    // Callback to the original function.
    FARPROC *orig;

    // Is this a "special" hook?
    int special;

    // Address of the hooked function.
    uint8_t *addr;

    // Amount of bytes to skip before placing the hook. I.e., hook
    // at addr+skip instead of addr.
    uint32_t skip;

    // Total size used to create our stub off.
    int32_t stub_used;

    // Is this function already hooked?
    uint32_t is_hooked;

    // Stub for calling the original function.
    uint8_t *func_stub;
} hook_t;

// Hook initialization part one and two. One should be called before having
// initialized the native functionality for memory allocation, two afterwards.
void hook_init(HMODULE module_handle);
void hook_init2();

int lde(const void *addr);

int hook_in_monitor();

int hook(hook_t *h);

#define DISASM_BUFSIZ 128

int disasm(const void *addr, char *str);

extern hook_t g_hooks[];

#endif
