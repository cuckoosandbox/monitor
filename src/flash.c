/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2018 Cuckoo Foundation.

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

#include <stdio.h>
#include <stdint.h>
#include "assembly.h"
#include "flash.h"
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "pipe.h"
#include "symbol.h"
#include "utf8.h"

static funcoff_t _MethodInfo_getMethodName_ts[] = {
    {0x565123f2, 0x6ee8f0, 0},
    {0, 0, 0},
};

static void *(__stdcall *g_flash_get_method_name)(uintptr_t method_name);

static uint8_t *g_module_address;

void flash_init(hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

    g_module_address = module_address;

    FARPROC addr = (FARPROC) module_addr_timestamp(
        module_address, module_size, _MethodInfo_getMethodName_ts, NULL
    );

    uint8_t *mem = hook_get_mem();
    *(uint8_t **) &g_flash_get_method_name = mem;

#if __x86_64__
    mem += asm_push_register(mem, R_RDX);
    mem += asm_pop_register(mem, R_RCX);
    mem += asm_move_regimm(mem, R_RDX, 0);
#else
    mem += asm_push_stack_offset(mem, 4);
    mem += asm_pop_register(mem, R_ECX);
    mem += asm_move_regimm(mem, R_EDX, 0);
#endif

    mem += asm_call(mem, addr);

#if __x86_64__
    mem += asm_return(mem, 0);
#else
    mem += asm_return(mem, 4);
#endif
}

const char *flash_get_method_name(uintptr_t method_name, uint32_t *length)
{
    void *ptr = g_flash_get_method_name(method_name);

    // TODO May need tweaking on 64-bit.
    *length = (uintptr_t) deref(ptr, 16);
    return deref(ptr, 8);
}

uintptr_t flash_module_offset(uintptr_t addr)
{
    return (uint8_t *) addr - g_module_address;
}
