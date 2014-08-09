/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2014 Cuckoo Foundation.

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
#include "slist.h"

typedef struct _hook_info_t {
    uint32_t hook_count;
    uint32_t last_error;

    slist_t retaddr;
} hook_info_t;

typedef struct _hook_data_t {
    uint8_t *trampoline;
    uint8_t *guide;
    uint8_t *func_stub;
    uint8_t *clean;

    uint8_t *_mem;
} hook_data_t;

typedef struct _hook_t {
    const char *library;
    const char *funcname;
    FARPROC handler;
    FARPROC *orig;
    uint8_t *addr;

    hook_data_t *data;
} hook_t;

hook_info_t *hook_alloc();
hook_info_t *hook_info();

void hook_disable();
void hook_enable();

int hook(const char *library, const char *funcname,
    FARPROC handler, FARPROC *orig);

int hook2(hook_t *h);

extern const hook_t g_hooks[];

#endif
