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

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "hooking.h"
#include "pipe.h"
#include "symbol.h"

#if __x86_64__

static uint8_t *_addr_colescript_compile(
    uint8_t *module_address, uintptr_t module_size, uintptr_t eval_code_addr)
{
    (void) module_address; (void) module_size; (void) eval_code_addr;

    uint8_t *code_ptr = NULL;

    // Locate 'lea rax, "eval code"' instruction.
    for (uint32_t idx = 0; idx < eval_code_addr - 20; idx++) {
        if(memcmp(&module_address[idx], "\x48\x8d\x05", 3) != 0) {
            continue;
        }

        uintptr_t addr = (uintptr_t) &module_address[idx] +
            *(int32_t *)(&module_address[idx] + 3) + 7;
        if(addr == eval_code_addr) {
            code_ptr = &module_address[idx];
            break;
        }
    }

    if(code_ptr == NULL) {
        return NULL;
    }

    // Get the address passed along to the first call instruction.
    for (uint32_t idx = 0; idx < 20; idx++) {
        if(*code_ptr == 0xe8) {
            return code_ptr + *(int32_t *)(code_ptr + 1) + 5;
        }

        code_ptr += lde(code_ptr);
    }

    return NULL;
}

#else

#define ASM_MAGIC \
    "\x6a\x00\x6a\x00\x6a\x02\x8d\x44\x24\x30\x50\x8b\xc7\x8b\xde\xe8"

static uint8_t *_addr_colescript_compile(
    uint8_t *module_address, uintptr_t module_size, uintptr_t eval_code_addr)
{
    // Currently unsupported due to compiler optimizations with regards to
    // the usage of registers.
    return NULL;

    uint8_t bytes[] = {
        0x68,
        (eval_code_addr >>  0) & 0xff,
        (eval_code_addr >>  8) & 0xff,
        (eval_code_addr >> 16) & 0xff,
        (eval_code_addr >> 24) & 0xff,
    };

    // Locate 'push "eval code"' instruction.
    uint8_t *code_ptr = NULL;
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        if(memcmp(&module_address[idx], bytes, sizeof(bytes)) == 0) {
            code_ptr = &module_address[idx];
            break;
        }
    }

    if(code_ptr == NULL) {
        return NULL;
    }

    // Given the unconventional calling convention we hardcode this for now.
    if(memcmp(code_ptr + 5, ASM_MAGIC, sizeof(ASM_MAGIC)-1) == 0) {
        code_ptr += 5 + sizeof(ASM_MAGIC)-2;
        return code_ptr + *(int32_t *)(code_ptr + 1);
    }

    pipe("DEBUG:JsEval to COleScript::Compile stub @ 0x%x", code_ptr);
    return NULL;
}

#endif

uint8_t *hook_addrcb_COleScript_Compile(hook_t *h, uint8_t *module_address)
{
    (void) h;

    uint32_t module_size = module_image_size(module_address);
    uintptr_t eval_code_addr = 0;

    // Locate address of the "eval code" string.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        if(memcmp(&module_address[idx], L"eval code", 20) == 0) {
            eval_code_addr = (uintptr_t) &module_address[idx];
            break;
        }
    }

    if(eval_code_addr == 0) {
        return NULL;
    }

    return _addr_colescript_compile(
        module_address, module_size, eval_code_addr);
}

#if __x86_64__

static uint8_t *_addr_cdocument_write(
    uint8_t *module_address, uintptr_t module_size, uintptr_t newline_addr)
{
    // Locate 'lea rdx, "\r\n"' instruction. There are a couple of these, so
    // we have to do a little bit of further selection.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        if(memcmp(&module_address[idx], "\x48\x8d\x15", 3) != 0) {
            continue;
        }

        uintptr_t addr = (uintptr_t) &module_address[idx] +
            *(int32_t *)(&module_address[idx] + 3) + 7;
        if(addr != newline_addr) {
            continue;
        }

        // If we scan back to the top of the function then we should find
        // two relative calls of which one is immediately followed by a test
        // instruction. This signature is unique among the code paths where
        // the "\r\n" string is used.
        for (uint32_t jdx = 0; jdx < 256; jdx++) {
            // The top is denoted by "push rbx ; sub rsp, 0x20".
            if(memcmp(&module_address[idx - jdx],
                    "\xff\xf3\x48\x83\xec", 5) != 0) {
                continue;
            }

            // Now locate both call instructions.
            uint8_t *ptr = &module_address[idx - jdx];
            uint8_t *addr1 = NULL, *addr2 = NULL;

            while (ptr < &module_address[idx]) {
                if(*ptr == 0xe8) {
                    if(addr1 == NULL) {
                        addr1 = ptr;
                    }
                    // Only two call instructions, not more, not less.
                    else if(addr2 != NULL) {
                        addr1 = addr2 = NULL;
                        break;
                    }
                    else {
                        addr2 = ptr;
                    }
                }

                ptr += lde(ptr);
            }

            // The second call is followed by a test instruction.
            if(addr2 != NULL && addr2[5] == 0x85) {
                return addr1 + *(int32_t *)(addr1 + 1) + 5;
            }
        }
    }

    return NULL;
}

#else

static uint8_t *_addr_cdocument_write(
    uint8_t *module_address, uintptr_t module_size, uintptr_t newline_addr)
{
    (void) module_address; (void) module_size; (void) newline_addr;
    return NULL;
}

#endif

uint8_t *hook_addrcb_CDocument_write(hook_t *h, uint8_t *module_address)
{
    (void) h;

    uint32_t module_size = module_image_size(module_address);
    uintptr_t newline_addr = 0;

    // Locate a possible address of the "\r\n" string.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        if(memcmp(&module_address[idx], L"\r\n", 6) == 0) {
            newline_addr = (uintptr_t) &module_address[idx];

            uint8_t *ret = _addr_cdocument_write(
                module_address, module_size, newline_addr);
            if(ret != NULL) {
                return ret;
            }
        }
    }

    return NULL;
}
