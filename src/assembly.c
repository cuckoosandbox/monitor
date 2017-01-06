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

#include <stdint.h>
#include <string.h>
#include "assembly.h"
#include "misc.h"
#include "native.h"

#if __x86_64__

int asm_move_regimm(uint8_t *stub, register_t reg, uintptr_t value)
{
    uint8_t *base = stub;

    stub += asm_push(stub, value);

    if(reg >= R_R8) {
        *stub++ = 0x41;
        *stub++ = 0x58 + (reg - R_R8);
    }
    else {
        *stub++ = 0x58 + reg;
        *stub++ = 0x90;
    }

    return stub - base;
}

int asm_push(uint8_t *stub, uintptr_t value)
{
    // Push the lower 32-bits of the value onto the stack. The 32-bit
    // value will be zero-extended to 64-bits.
    stub[0] = 0x68;
    *(uint32_t *)(stub + 1) = (uint32_t) value;

    // Move higher 32-bits of the value into the stack.
    // mov dword [rsp+4], 32-bit
    stub[5] = 0xc7;
    stub[6] = 0x44;
    stub[7] = 0x24;
    stub[8] = 0x04;
    *(uint32_t *)(stub + 9) = (uint32_t)(value >> 32);
    return 13;
}

int asm_jregz(uint8_t *stub, register_t reg, int8_t offset)
{
    if(reg < R_R8) {
        *stub++ = 0x48;
    }
    else {
        *stub++ = 0x4d;
        reg -= R_R8;
    }
    *stub++ = 0x85;
    *stub++ = 0xc0 + reg + reg * 8;
    *stub++ = 0x74;
    *stub++ = offset;
    return 5;
}

#else

int asm_move_regimm(uint8_t *stub, register_t reg, uintptr_t value)
{
    *stub = 0xb8 + reg;
    *(uintptr_t *)(stub + 1) = value;
    return 5;
}

int asm_push(uint8_t *stub, uintptr_t value)
{
    return asm_push32(stub, value);
}

int asm_jregz(uint8_t *stub, register_t reg, int8_t offset)
{
    *stub++ = 0x85;
    *stub++ = 0xc0 + reg + reg * 8;
    *stub++ = 0x74;
    *stub++ = offset;
    return 4;
}

#endif

int asm_push_register(uint8_t *stub, register_t reg)
{
#if __x86_64__
    if(reg >= R_R8) {
        *stub++ = 0x41;
        *stub++ = 0x50 + (reg - R_R8);
        return 2;
    }
    else {
        *stub++ = 0x50 + reg;
        return 1;
    }
#else
    *stub++ = 0x50 + reg;
    return 1;
#endif
}

int asm_add_regimm(uint8_t *stub, register_t reg, uint32_t value)
{
#if __x86_64__
    if(reg >= R_R8) {
        stub[0] = 0x49;
        reg -= R_R8;
    }
    else {
        stub[0] = 0x90;
    }
#else
    stub[0] = 0x90;
#endif

    stub[1] = 0x81;
    stub[2] = 0xc0 + reg;
    *(uint32_t *)(stub + 3) = value;
    return 7;
}

int asm_add_esp_imm(uint8_t *stub, uint32_t value)
{
#if __x86_64__
    return asm_lea_regregimm(stub, R_RSP, R_RSP, value);
#else
    return asm_lea_regregimm(stub, R_ESP, R_ESP, value);
#endif
}

int asm_sub_regimm(uint8_t *stub, register_t reg, uint32_t value)
{
#if __x86_64__
    if(reg >= R_R8) {
        stub[0] = 0x49;
        reg -= R_R8;
    }
    else {
        stub[0] = 0x90;
    }
#else
    stub[0] = 0x90;
#endif

    stub[1] = 0x81;
    stub[2] = 0xe8 + reg;
    *(uint32_t *)(stub + 3) = value;
    return 7;
}

int asm_lea_regregimm(
    uint8_t *stub, register_t dst, register_t src, uint32_t value)
{
#if __x86_64__
    (void) stub; (void) dst; (void) src; (void) value;
    return -1;
#else
    stub[0] = 0x8d;
    stub[1] = 0x80 + dst * 8 + src;
    if(src == R_ESP) {
        stub[2] = 0x24;
        *(uint32_t *)(stub + 3) = value;
    }
    else {
        *(uint32_t *)(stub + 2) = value;
        stub[6] = 0x90;
    }
    return 7;
#endif
}

int asm_sub_esp_imm(uint8_t *stub, uint32_t value)
{
#if __x86_64__
    return asm_lea_regregimm(stub, R_RSP, R_RSP, -value);
#else
    return asm_lea_regregimm(stub, R_ESP, R_ESP, -value);
#endif
}

int asm_jump_32bit(uint8_t *stub, const void *addr)
{
#if DEBUG && !__x86_64__
    stub[0] = 0x68;
    stub[5] = 0xc3;
    *(uint32_t *)(stub + 1) = (uint32_t) (uintptr_t) addr;
    return 6;
#else
    stub[0] = 0xe9;
    *(uint32_t *)(stub + 1) = (uint8_t *) addr - stub - 5;
    return 5;
#endif
}

int asm_jump_32bit_rel(uint8_t *stub, const void *addr, int relative)
{
    stub[0] = 0x0f;
    stub[1] = 0x80 + relative;
    *(uint32_t *)(stub + 2) = (uint8_t *) addr - stub - 6;
    return 6;
}

int asm_jump(uint8_t *stub, const void *addr)
{
    uint8_t *base = stub;

    // Push the address on the stack.
    stub += asm_pushv(stub, addr);

    // Pop the address into the instruction pointer.
    *stub++ = 0xc3;

    return stub - base;
}

int asm_call(uint8_t *stub, const void *addr)
{
    uint8_t *base = stub;

#if __x86_64__
    stub += asm_move_regimmv(stub, R_RAX, addr);
#else
    stub += asm_move_regimmv(stub, R_EAX, addr);
#endif

    *stub++ = 0xff;
    *stub++ = 0xd0;

    return stub - base;
}

int asm_return(uint8_t *stub, uint16_t value)
{
    uint8_t *base = stub;

    *stub++ = 0xc2;
    *stub++ = value & 0xff;
    *stub++ = value >> 8;

    return stub - base;
}

int asm_push32(uint8_t *stub, uintptr_t value)
{
    // Push the value onto the stack.
    stub[0] = 0x68;
    *(uintptr_t *)(stub + 1) = value;
    return 5;
}

int asm_push_context(uint8_t *stub)
{
    uint8_t *base = stub;

#if __x86_64__
#else
    // pushfd
    *stub++ = 0x9c;
    // pushad
    *stub++ = 0x60;
#endif

    return stub - base;
}

int asm_pop_context(uint8_t *stub)
{
    uint8_t *base = stub;

#if __x86_64__
#else
    // popad
    *stub++ = 0x61;
    // popfd
    *stub++ = 0x9d;
#endif

    return stub - base;
}

int asm_push_stack_offset(uint8_t *stub, uint32_t offset)
{
    uint8_t *base = stub;

    *stub++ = 0xff;
    if(offset < 0x80) {
        *stub++ = 0x74;
        *stub++ = 0x24;
        *stub++ = offset;
    }
    else {
        *stub++ = 0xb4;
        *stub++ = 0x24;
        *(uint32_t *) stub = offset;
        stub += 4;
    }

    return stub - base;
}

uint8_t *asm_get_rel_jump_target(uint8_t *addr)
{
    if(*addr == 0xeb) {
        return addr + *(int8_t *)(addr + 1) + 2;
    }
    if(*addr == 0xe9) {
        return addr + *(int32_t *)(addr + 1) + 5;
    }
    return NULL;
}

uint8_t *asm_get_rel_call_target(uint8_t *addr)
{
    if(*addr == 0xe8) {
        return addr + *(int32_t *)(addr + 1) + 5;
    }
    return NULL;
}

uint8_t *asm_get_call_target(uint8_t *addr)
{
    uint8_t *ret = asm_get_rel_call_target(addr);
    if(ret == NULL && *addr == 0xff && addr[1] == 0x15) {
#if __x86_64__
        addr += *(int32_t *)(addr + 2) + 6;
        ret = *(uint8_t **) addr;
#else
        ret = **(uint8_t ***)(addr + 2);
#endif
    }
    return ret;
}

int asm_is_abs_call(uint8_t *addr)
{
    if(*addr != 0xff || addr[1] != 0x15) {
        return 0;
    }
    return 1;
}

int asm_is_call_function(uint8_t *addr,
    const wchar_t *library, const char *funcname)
{
    if(*addr != 0xff || addr[1] != 0x15) {
        return 0;
    }

#if __x86_64__
    addr += *(int32_t *)(addr + 2) + 6;
#else
    addr = *(uint8_t **)(addr + 2);
#endif

    // TODO We should perhaps use range_is_readable() here, but then inject.c
    // will require every other dependency in the project, resulting in
    // 500kb inject-{x86,x64}.exe files, which is kind of bloated.
    addr = *(uint8_t **) addr;

    HMODULE module_handle = GetModuleHandleW(library);
    if(module_handle == NULL) {
        return 0;
    }

    FARPROC fp = GetProcAddress(module_handle, funcname);
    return (uint8_t *) fp == addr;
}
