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

#else

int asm_move_regimm(uint8_t *stub, register_t reg, uintptr_t value)
{
    uint8_t *base = stub;

    *stub = 0xb8 + reg;
    *(uintptr_t *)(stub + 1) = value;
    return 5;
}

int asm_push(uint8_t *stub, uintptr_t value)
{
    // Push the value onto the stack.
    stub[0] = 0x68;
    *(const uintptr_t **)(stub + 1) = value;
    return 5;
}

#endif

int asm_jump_32bit(uint8_t *stub, void *addr)
{
    stub[0] = 0xe9;
    *(uint32_t *)(stub + 1) = (uint8_t *) addr - stub - 5;
    return 5;
}

int asm_jump(uint8_t *stub, void *addr)
{
    uint8_t *base = stub;

    // Push the address on the stack.
    stub += asm_pushv(stub, addr);

    // Pop the address into the instruction pointer.
    *stub++ = 0xc3;

    return stub - base;
}

int asm_call(uint8_t *stub, void *addr)
{
    uint8_t *base = stub;

    // We push the return address onto the stack and then jump into the target
    // address. This way both 32-bit and 64-bit are supported at once. The
    // return address is 8-byte aligned as required in 64-bit mode.
    uint8_t *return_address = stub + ASM_PUSH_SIZE + ASM_JUMP_ADDR_SIZE;
    return_address += 8 - ((uintptr_t) return_address & 7);

    stub += asm_pushv(stub, return_address);
    stub += asm_jump(stub, addr);

    // Pad with a couple of int3's.
    memset(stub, 0xcc, return_address - stub);

    return return_address - base;
}

int asm_return(uint8_t *stub, uint16_t value)
{
    uint8_t *base = stub;

    *stub++ = 0xc2;
    *stub++ = value & 0xff;
    *stub++ = value >> 8;

    return stub - base;
}
