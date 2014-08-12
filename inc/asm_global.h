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

#ifndef MONITOR_ASMGLOBAL_H
#define MONITOR_ASMGLOBAL_H

#include <stdint.h>

extern const uint8_t *asm_tramp;
extern const uint32_t asm_tramp_size;
extern const uint32_t asm_tramp_hook_alloc_off;
extern const uint32_t asm_tramp_hook_handler_off;
extern const uint32_t asm_tramp_orig_func_stub_off;
extern const uint32_t asm_tramp_retaddr_off;
extern const uint32_t asm_tramp_retaddr_add_off;

extern const uint8_t *asm_tramp_special;
extern const uint32_t asm_tramp_special_size;
extern const uint32_t asm_tramp_special_hook_alloc_off;
extern const uint32_t asm_tramp_special_hook_handler_off;
extern const uint32_t asm_tramp_special_orig_func_stub_off;
extern const uint32_t asm_tramp_special_retaddr_off;
extern const uint32_t asm_tramp_special_retaddr_add_off;

extern const uint8_t *asm_guide;
extern const uint32_t asm_guide_size;
extern const uint32_t asm_guide_orig_stub_off;
extern const uint32_t asm_guide_retaddr_add_off;
extern const uint32_t asm_guide_retaddr_pop_off;

extern const uint8_t *asm_clean;
extern const uint32_t asm_clean_size;
extern const uint32_t asm_clean_retaddr_pop_off;

#endif
