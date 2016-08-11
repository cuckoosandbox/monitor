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

#ifndef MONITOR_ASSEMBLY_H
#define MONITOR_ASSEMBLY_H

#include <stdint.h>

#if __x86_64__

#define ASM_MOVE_REGIMM_SIZE (ASM_PUSH_SIZE+2)
#define ASM_PUSH_SIZE 13
#define ASM_JREGZ 5
#define ASM_JUMP_SIZE 14

typedef enum _register_t {
    R_RAX, R_RCX, R_RDX, R_RBX, R_RSP, R_RBP, R_RSI, R_RDI,
    R_R8,  R_R9,  R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,

    R_R0 = R_RAX,
} register_t;

#else

#define ASM_MOVE_REGIMM_SIZE 5
#define ASM_PUSH_SIZE 5
#define ASM_JREGZ 4
#define ASM_JUMP_SIZE 6

typedef enum _register_t {
    R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI,

    R_R0 = R_EAX,
} register_t;

#endif

#define ASM_ADD_REGIMM_SIZE 7
#define ASM_CALL_SIZE (ASM_MOVE_REGIMM_SIZE+2)
#define ASM_RETURN_SIZE 3

#if DEBUG && !__x86_64__
#define ASM_JUMP_32BIT_SIZE 6
#else
#define ASM_JUMP_32BIT_SIZE 5
#endif

int asm_move_regimm(uint8_t *stub, register_t reg, uintptr_t value);
int asm_push(uint8_t *stub, uintptr_t value);
int asm_push32(uint8_t *stub, uintptr_t value);
int asm_push_register(uint8_t *stub, register_t reg);
int asm_jregz(uint8_t *stub, register_t reg, int8_t offset);
int asm_jump_32bit(uint8_t *stub, const void *addr);
int asm_jump_32bit_rel(uint8_t *stub, const void *addr, int relative);
int asm_add_regimm(uint8_t *stub, register_t reg, uint32_t value);
int asm_add_esp_imm(uint8_t *stub, uint32_t value);
int asm_sub_regimm(uint8_t *stub, register_t reg, uint32_t value);
int asm_sub_esp_imm(uint8_t *stub, uint32_t value);
int asm_lea_regregimm(
    uint8_t *stub, register_t dst, register_t src, uint32_t value
);
int asm_jump(uint8_t *stub, const void *addr);
int asm_call(uint8_t *stub, const void *addr);
int asm_return(uint8_t *stub, uint16_t value);
int asm_push_context(uint8_t *stub);
int asm_pop_context(uint8_t *stub);
int asm_push_stack_offset(uint8_t *stub, uint32_t offset);

static inline int asm_move_regimmv(uint8_t *stub,
    register_t reg, const void *value)
{
    return asm_move_regimm(stub, reg, (uintptr_t) value);
}

static inline int asm_pushv(uint8_t *stub, const void *value)
{
    return asm_push(stub, (uintptr_t) value);
}

uint8_t *asm_get_rel_jump_target(uint8_t *addr);
uint8_t *asm_get_rel_call_target(uint8_t *addr);
uint8_t *asm_get_call_target(uint8_t *addr);

int asm_is_call_function(uint8_t *addr,
    const wchar_t *library, const char *funcname);
int asm_is_abs_call(uint8_t *addr);

#endif
