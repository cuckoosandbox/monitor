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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include "asm_global.h"
#include "assembly.h"
#include "capstone/include/capstone.h"
#include "capstone/include/x86.h"
#include "hooking.h"
#include "ntapi.h"
#include "pipe.h"
#include "slist.h"
#include "unhook.h"

#if __x86_64__
#define TLS_HOOK_INFO 0x80
#else
#define TLS_HOOK_INFO 0x44
#endif

hook_info_t *hook_alloc()
{
    hook_info_t *ret = (hook_info_t *) calloc(1, sizeof(hook_info_t));
    slist_init(&ret->retaddr, 128);
    writetls(TLS_HOOK_INFO, (uintptr_t) ret);
    return ret;
}

hook_info_t *hook_info()
{
    hook_info_t *ret = (hook_info_t *) readtls(TLS_HOOK_INFO);
    if(ret == NULL) {
        ret = hook_alloc();
    }
    return ret;
}

void __stdcall hook_retaddr_add(uintptr_t retaddr)
{
    hook_info_t *h = hook_info();
    slist_push(&h->retaddr, retaddr);
}

uintptr_t __stdcall hook_retaddr_pop()
{
    hook_info_t *h = hook_info();
    return slist_pop(&h->retaddr);
}

void hook_disable()
{
    hook_info()->hook_count++;
}

void hook_enable()
{
    hook_info()->hook_count--;
}

int lde(const void *addr)
{
    static int capstone_init = 0; static csh capstone;

    if(capstone_init == 0) {
#if __x86_64__
        cs_open(CS_ARCH_X86, CS_MODE_64, &capstone);
#else
        cs_open(CS_ARCH_X86, CS_MODE_32, &capstone);
#endif
        capstone_init = 1;
    }

    cs_insn *insn;

    size_t count =
        cs_disasm_ex(capstone, addr, 16, (uintptr_t) addr, 1, &insn);
    if(count == 0) return 0;

    int size = insn->size;

    cs_free(insn, count);
    return size;
}

int hook_create_stub(uint8_t *tramp, const uint8_t *addr, int len)
{
    const uint8_t *base_addr = addr;

    while (len > 0) {
        int length = lde(addr);
        if(length == 0) return -1;

        // How many bytes left?
        len -= length;

        // Unconditional jump with 32-bit relative offset.
        if(*addr == 0xe9) {
            const uint8_t *target = addr + *(int32_t *)(addr + 1) + 5;
            tramp += asm_jump_addr(tramp, target);
            addr += 5;
        }
        // Call with 32-bit relative offset.
        else if(*addr == 0xe8) {
            const uint8_t *target = addr + *(int32_t *)(addr + 1) + 5;
            tramp += asm_call_addr(tramp, target);
            addr += 5;
        }
        // Conditional jump with 32bit relative offset.
        else if(*addr == 0x0f && addr[1] >= 0x80 && addr[1] < 0x90) {

#if __x86_64__
            pipe("CRITICAL:Conditional jump and calls in 64-bit are "
                 "considered unstable!");
#endif

            // TODO This can be stabilized by creating a 8-bit conditional
            // jump with 32/64-bit jumps at each target. However, this is
            // only required for 64-bit support and then only when this
            // instruction occurs at all in the original function - which is
            // currently not the case.

            // Conditional jumps consist of two bytes.
            *tramp++ = addr[0];
            *tramp++ = addr[1];

            // When a jmp/call is performed, then the relative offset +
            // the instruction pointer + the size of the instruction is the
            // resulting address, so that's our target address.
            // As we have already written the first one or two bytes of the
            // instruction we only have the relative address left - four bytes
            // in total.
            const uint8_t *target = addr + *(int32_t *)(addr + 2) + 6;

            // We have already copied the instruction opcode(s) itself so we
            // just have to calculate the relative address now.
            *(uint32_t *) tramp = target - tramp - 4;
            tramp += 4;

            addr += 6;
        }
        // Unconditional jump with 8bit relative offset.
        else if(*addr == 0xeb) {
            const uint8_t *target = addr + *(int8_t *)(addr + 1) + 2;
            tramp += asm_jump_addr(tramp, target);
            addr += 2;

            // TODO Check the remaining length. Also keep in mind that any
            // following nop's behind this short jump can be included in the
            // remaining available space.
        }
        // Conditional jump with 8bit relative offset.
        else if(*addr >= 0x70 && *addr < 0x80) {

#if __x86_64__
            pipe("CRITICAL:Conditional jumps in 64-bit are "
                 "considered unstable!");
#endif

            // TODO The same as for the 32-bit conditional jumps.

            // Same rules apply as with the 32bit relative offsets, except
            // for the fact that both conditional and unconditional 8bit
            // relative jumps take only one byte for the opcode.

            // Hex representation of the two types of 32bit jumps;
            // 8bit relative conditional jumps:     70..80
            // 32bit relative conditional jumps: 0f 80..90
            // Thus we have to add 0x10 to the opcode of 8bit relative
            // offset jump to obtain the 32bit relative offset jump
            // opcode.
            *tramp++ = 0x0f;
            *tramp++ = addr[0] + 0x10;

            // 8bit relative offset - we have to sign-extend it, by casting it
            // as signed char, in order to calculate the correct address.
            const uint8_t *target = addr + *(int8_t *)(addr + 1) + 2;

            // Calculate the relative address.
            *(uint32_t *) tramp = (uint32_t)(target - tramp - 4);
            tramp += 4;

            addr += 2;
        }
        // Return instruction indicates the end of basic block as well so we
        // have to check if we already have enough space for our hook..
        else if((*addr == 0xc3 || *addr == 0xc2) && len > 0) {
            return -1;
        }
        // This is a regular instruction - copy it right away.
        else {
            while (length-- != 0) {
                *tramp++ = *addr++;
            }
        }
    }

    // Jump to the original function at the point where our stub ends.
    tramp += asm_jump_addr(tramp, addr);
    return addr - base_addr;
}

#if __x86_64__

// We scan 500mb below and above the address - in general this should be
// more than enough to find a hole in which we place our intermediate jumps.
#define CLOSEBY_RANGE 0x20000000

static uint8_t *_hook_alloc_closeby_ptr(uint8_t **last_ptr, uint32_t size)
{
    uint8_t *ret = *last_ptr;
    *last_ptr += size + (8 - (size & 7));

    // We reached the next page - reset the pointer.
    if(((uintptr_t) *last_ptr & 0xfff) == 0) {
        *last_ptr = NULL;
    }
    return ret;
}

static uint8_t *_hook_alloc_closeby(uint8_t *target, uint32_t size)
{
    static uint8_t *last_ptr = NULL;
    DWORD old_protect; SYSTEM_INFO si; MEMORY_BASIC_INFORMATION mbi;

    GetSystemInfo(&si);

    if(last_ptr != NULL && last_ptr >= target - CLOSEBY_RANGE &&
            last_ptr < target + CLOSEBY_RANGE) {
        return _hook_alloc_closeby_ptr(&last_ptr, size);
    }

    for (uint8_t *addr = target - CLOSEBY_RANGE;
            addr < target + CLOSEBY_RANGE;
            addr += si.dwAllocationGranularity) {

        if(VirtualQueryEx(GetCurrentProcess(), addr, &mbi,
                sizeof(mbi)) == FALSE || mbi.State != MEM_FREE) {
            continue;
        }

        if(VirtualAllocEx(GetCurrentProcess(), mbi.BaseAddress,
                si.dwPageSize, MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE) == NULL) {
            continue;
        }

        // TODO Do we really need this?
        if(VirtualProtectEx(GetCurrentProcess(), mbi.BaseAddress,
                si.dwPageSize, PAGE_EXECUTE_READWRITE,
                &old_protect) != FALSE) {
            memset(mbi.BaseAddress, 0xcc, si.dwPageSize);
            last_ptr = mbi.BaseAddress;
            return _hook_alloc_closeby_ptr(&last_ptr, size);
        }
    }
    return NULL;
}

int hook_create_jump(uint8_t *addr, uint8_t *target, int stub_used)
{
    unsigned long old_protect;

    if(VirtualProtect(addr, stub_used, PAGE_EXECUTE_READWRITE,
            &old_protect) == FALSE) {
        return -1;
    }

    // As the target is probably not close enough addr for a 32-bit relative
    // jump we allocate a separate page for an intermediate jump.
    uint8_t *closeby = _hook_alloc_closeby(addr, ASM_JUMP_ADDR_SIZE);

    // Nop all used bytes out with int3's.
    memset(addr, 0xcc, stub_used);

    // Jump from the hooked address to our intermediate jump. The intermediate
    // jump address is within the 32-bit range a 32-bit jump can handle.
    asm_jump_32bit(addr, closeby);

    // Jump from the intermediate jump to the target address. This is a full
    // 64-bit jump.
    asm_jump_addr(closeby, target);

    VirtualProtect(addr, stub_used, old_protect, &old_protect);
    return 0;
}

#else

int hook_create_jump(uint8_t *addr, const uint8_t *target, int stub_used)
{
    unsigned long old_protect;

    if(VirtualProtect(addr, stub_used, PAGE_EXECUTE_READWRITE,
            &old_protect) == FALSE) {
        return -1;
    }

    // Pad all used bytes out with int3's.
    memset(addr, 0xcc, stub_used);

    // Jump from the hooked address to the target address.
    asm_jump_32bit(addr, target);

    VirtualProtect(addr, stub_used, old_protect, &old_protect);
    return 0;
}

#endif

static uint8_t *_hook_follow_jumps(const char *funcname, uint8_t *addr)
{
    // Under Windows 7 some functions have been replaced by a function stub
    // which in turn calls the original function. E.g., a lot of functions
    // which originaly went through kernel32.dll now make a pass through
    // kernelbase.dll before reaching kernel32.dll.
    // We follow these jumps and add the regions to the list for unhook
    // detection.

    while (1) {
        // jmp short imm8
        if(*addr == 0xeb) {
            unhook_detect_add_region(funcname, addr, addr, addr, 2);
            addr = addr + 2 + *(signed char *)(addr + 1);
            continue;
        }

        // jmp dword [addr]
        if(*addr == 0xff && addr[1] == 0x25) {
            unhook_detect_add_region(funcname, addr, addr, addr, 6);

#if __x86_64__
            addr += *(uint32_t *)(addr + 2) + 6;
#else
            addr = *(uint8_t **)(addr + 2);
#endif

            unhook_detect_add_region(funcname, addr, addr, addr, 4);
            addr = *(uint8_t **) addr;
            continue;
        }

        // mov edi, edi ; push ebp ; mov ebp, esp ; pop ebp ; jmp short imm8
        if(!memcmp(addr, "\x8b\xff\x55\x8b\xec\x5d\xeb", 7)) {
            unhook_detect_add_region(funcname, addr, addr, addr, 8);
            addr = addr + 8 + *(signed char *)(addr + 7);
            continue;
        }

        break;
    }

    return addr;
}

#define PATCH(buf, off, value) \
    *(uintptr_t *)(buf + off) = (uintptr_t) value

int hook2(hook_t *h)
{
    hook_data_t *hd = h->data =
        (hook_data_t *) calloc(1, sizeof(hook_data_t));

    // We allocate 64 bytes for the function stub and 64 bytes for padding
    // in-between (for debugging purposes.)
    uint32_t mem_size =
        asm_tramp_size + asm_guide_size + asm_clean_size + 64 + 64;
    hd->_mem = (uint8_t *) malloc(mem_size);
    memset(hd->_mem, 0xcc, mem_size);

    unsigned long old_protect;
    VirtualProtect(hd->_mem, mem_size, PAGE_EXECUTE_READWRITE, &old_protect);

    // Assign memory for each stub. Do note that for 64-bit support we require
    // that every stub is 8-byte aligned - we enforce this also for x86.
    hd->trampoline = hd->_mem;

    hd->guide = hd->trampoline + 16 + asm_tramp_size;
    hd->guide = (uint8_t *)((uintptr_t) hd->guide & ~7);

    hd->clean = hd->guide + 16 + asm_guide_size;
    hd->clean = (uint8_t *)((uintptr_t) hd->clean & ~7);

    hd->func_stub = hd->clean + 16 + asm_clean_size;
    hd->func_stub = (uint8_t *)((uintptr_t) hd->func_stub & ~7);

    *h->orig = (FARPROC) hd->guide;

    // Create the original function stub.
    int stub_used = hook_create_stub(hd->func_stub, h->addr, 5);
    if(stub_used < 0) {
        pipe("CRITICAL:Error creating function stub for %z!%z.",
            h->library, h->funcname);
        return -1;
    }

    // Copy all buffers and patch a couple of pointers.
    memcpy(hd->trampoline, asm_tramp, asm_tramp_size);
    PATCH(hd->trampoline, asm_tramp_hook_alloc_off, hook_alloc);
    PATCH(hd->trampoline, asm_tramp_hook_handler_off, h->handler);
    PATCH(hd->trampoline, asm_tramp_orig_func_stub_off, hd->func_stub);
    PATCH(hd->trampoline, asm_tramp_retaddr_off, hd->clean);
    PATCH(hd->trampoline, asm_tramp_retaddr_add_off, hook_retaddr_add);

    memcpy(hd->guide, asm_guide, asm_guide_size);
    PATCH(hd->guide, asm_guide_orig_stub_off, hd->func_stub);
    PATCH(hd->guide, asm_guide_retaddr_add_off, hook_retaddr_add);
    PATCH(hd->guide, asm_guide_retaddr_pop_off, hook_retaddr_pop);

    memcpy(hd->clean, asm_clean, asm_clean_size);
    PATCH(hd->clean, asm_clean_retaddr_pop_off, hook_retaddr_pop);

    uint8_t region_original[32];
    memcpy(region_original, h->addr, stub_used);

    // Patch the original function.
    if(hook_create_jump(h->addr, hd->trampoline, stub_used) < 0) {
        pipe("CRITICIAL:Error creating function jump for %z!%z.",
            h->library, h->funcname);
        return -1;
    }

    unhook_detect_add_region(h->funcname, h->addr, region_original,
        h->addr, stub_used);

    return 0;
}

int hook(const char *library, const char *funcname,
    FARPROC handler, FARPROC *orig)
{
    HMODULE module_handle = GetModuleHandle(library);
    if(module_handle == NULL) return 0;

    FARPROC addr = GetProcAddress(module_handle, funcname);
    if(addr == NULL) {
        pipe("CRITICAL:Error resolving function %z!%z.", library, funcname);
        return -1;
    }

    hook_t h;
    h.library = library;
    h.funcname = funcname;
    h.handler = handler;
    h.orig = orig;
    h.addr = _hook_follow_jumps(funcname, (uint8_t *) addr);
    return hook2(&h);
}
