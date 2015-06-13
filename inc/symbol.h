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

#ifndef MONITOR_SYMBOL_H
#define MONITOR_SYMBOL_H

#include <stdint.h>
#include <windows.h>

#if __x86_64__
#define IMAGE_NT_HEADERS_CROSS IMAGE_NT_HEADERS64
#else
#define IMAGE_NT_HEADERS_CROSS IMAGE_NT_HEADERS
#endif

typedef void (*symbol_callback_t)(const char *funcname,
    uintptr_t address, void *context);

void symbol_init(HMODULE monitor_address);
uint32_t module_image_size(const uint8_t *addr);

int symbol_enumerate_module(HMODULE module_handle,
    symbol_callback_t callback, void *context);

int symbol(const uint8_t *addr, char *sym, uint32_t length);

#endif
