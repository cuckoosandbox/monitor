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
    const char *library;
    const char *funcname;
    FARPROC handler;
    FARPROC *orig;
    int special;
    os_version_t minimum_os;

    uint8_t *addr;
    uint32_t is_hooked;

    uint8_t *func_stub;
    int32_t stub_used;
} hook_t;

void hook_init(HMODULE module_handle, int custom_allocator);

int lde(const void *addr);

int hook_in_monitor();

int hook(hook_t *h);

#define DISASM_BUFSIZ 128

int disasm(const void *addr, char *str);

extern hook_t g_hooks[];

#endif
