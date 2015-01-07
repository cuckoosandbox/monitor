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
#define ASM_PUSH_ADDR_SIZE 13
#define ASM_JUMP_ADDR_SIZE 14
#else
#define ASM_PUSH_ADDR_SIZE 5
#define ASM_JUMP_ADDR_SIZE 6
#endif

#define ASM_JUMP_32BIT_SIZE 5

int asm_push_addr(uint8_t *stub, const uint8_t *addr);
int asm_jump_32bit(uint8_t *stub, const uint8_t *addr);
int asm_jump_addr(uint8_t *stub, const uint8_t *addr);
int asm_call_addr(uint8_t *stub, const uint8_t *addr);

#endif
