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
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include "assembly.h"
#include "capstone/include/capstone.h"
#include "capstone/include/x86.h"
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"
#include "unhook.h"

static SYSTEM_INFO g_si;
static csh g_capstone;

static uintptr_t g_monitor_start;
static uintptr_t g_monitor_end;

static uintptr_t g_ntdll_start;
static uintptr_t g_ntdll_end;

// Return address for Old_LdrLoadDll. Will be used later on to decide whether
// we are "inside" the monitor.
static uintptr_t g_Old_LdrLoadDll_address;

static void *_cs_malloc(size_t size)
{
    return mem_alloc(size);
}

static void *_cs_calloc(size_t nmemb, size_t size)
{
    return mem_alloc(nmemb * size);
}

static void *_cs_realloc(void *ptr, size_t size)
{
    return mem_realloc(ptr, size);
}

static void _cs_free(void *ptr)
{
    mem_free(ptr);
}

static void _capstone_init()
{
#if __x86_64__
    cs_open(CS_ARCH_X86, CS_MODE_64, &g_capstone);
#else
    cs_open(CS_ARCH_X86, CS_MODE_32, &g_capstone);
#endif
}

void hook_init(HMODULE module_handle)
{
    g_monitor_start = (uintptr_t) module_handle;
    g_monitor_end = g_monitor_start +
        module_image_size((const uint8_t *) module_handle);

    g_ntdll_start = (uintptr_t) GetModuleHandle("ntdll");
    g_ntdll_end = g_ntdll_start +
        module_image_size((const uint8_t *) g_ntdll_start);

    GetSystemInfo(&g_si);
    _capstone_init();
}

void hook_init2()
{
    if(g_capstone != 0) {
        cs_close(&g_capstone);
    }

    cs_opt_mem cs_mem;
    cs_mem.malloc = &_cs_malloc;
    cs_mem.calloc = &_cs_calloc;
    cs_mem.realloc = &_cs_realloc;
    cs_mem.free = &_cs_free;

    // TODO Is there an alternative besides doing your own implementation?
    cs_mem.vsnprintf = &vsnprintf;

    cs_option(0, CS_OPT_MEM, (size_t) (uintptr_t) &cs_mem);
    _capstone_init();
}

static uintptr_t WINAPI _hook_retaddr4(void *a, void *b, void *c, void *d)
{
    (void) a; (void) b; (void) c; (void) d;

    // Probably gcc specific.
    return (uintptr_t) __builtin_return_address(0);
}

void hook_initcb_LdrLoadDll(hook_t *h)
{
    FARPROC fn = *h->orig;

    *h->orig = (FARPROC) _hook_retaddr4;

    g_Old_LdrLoadDll_address = (uintptr_t) h->handler(NULL, 0, NULL, NULL);

    *h->orig = fn;
}

int hook_in_monitor()
{
    uintptr_t addrs[RETADDRCNT]; uint32_t count;
    int inside_LdrLoadDll = 0, outside_ntdll = 0, inside_monitor = 0;

    count = stacktrace(NULL, addrs, RETADDRCNT);

    // If an address that lies within the monitor DLL is found in the
    // stacktrace then we consider this call not interesting. Except for some
    // edge cases, please keep reading.
    for (uint32_t idx = count - 1; idx >= 2; idx--) {
        if(addrs[idx] >= g_monitor_start && addrs[idx] < g_monitor_end) {
            // If this address belongs to New_LdrLoadDll, our hook handler,
            // then we increase the following flag and continue. This helps us
            // with getting API logs for stuff happening in DllMain.
            if(addrs[idx] == g_Old_LdrLoadDll_address) {
                inside_LdrLoadDll++;
                continue;
            }

            // Inside monitor counts the amount of addresses inside the
            // monitor but without the LdrLoadDll entries.
            inside_monitor++;
            continue;
        }

        if(inside_LdrLoadDll != 0 && (
                addrs[idx] < g_ntdll_start || addrs[idx] > g_ntdll_end)) {
            outside_ntdll++;
        }
    }

    // Most common case. We are not inside LdrLoadDll and this is the first
    // occurrence of our monitor in the stacktrace.
    if(inside_LdrLoadDll == 0 && inside_monitor == 1) {
        return 0;
    }

    // Edge case. We are in LdrLoadDll and find ourselves to the first
    // non-LdrLoadDll occurrence of our monitor in the stacktrace. Or the
    // second of both, or third of both, etc. Also, at least one entry is
    // outside of ntdll, to filter LdrLoadDll's own calls.
    if(inside_LdrLoadDll != 0 && outside_ntdll != 0 &&
            inside_LdrLoadDll == inside_monitor) {
        return 0;
    }

    return 1;
}

int lde(const void *addr)
{
    if(g_capstone == 0) {
        MessageBox(NULL, "Capstone has not been initialized yet!",
            "Error", 0);
        return 0;
    }

    cs_insn *insn;

    size_t count =
        cs_disasm_ex(g_capstone, addr, 16, (uintptr_t) addr, 1, &insn);
    if(count == 0) return 0;

    int size = insn->size;

    cs_free(insn, count);
    return size;
}

int disasm(const void *addr, char *str)
{
    if(g_capstone == 0) {
        pipe("CRITICAL:Capstone has not been initialized yet!");
        return *str = 0, 0;
    }

    cs_insn *insn;

    size_t count =
        cs_disasm_ex(g_capstone, addr, 16, (uintptr_t) addr, 1, &insn);
    if(count == 0) return -1;

    our_snprintf(str, DISASM_BUFSIZ, "%s %s", insn->mnemonic, insn->op_str);

    cs_free(insn, count);
    return 0;
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
            tramp += asm_jump(tramp, target);
            addr += 5;
        }
        // Call with 32-bit relative offset.
        else if(*addr == 0xe8) {
            const uint8_t *target = addr + *(int32_t *)(addr + 1) + 5;
            tramp += asm_call(tramp, target);
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
            tramp += asm_jump(tramp, target);
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
    tramp += asm_jump(tramp, addr);
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
    if(((uintptr_t) ret & ~0xfff) !=
            ((uintptr_t)(*last_ptr + size + (8 - (size & 7))) & ~0xfff)) {
        *last_ptr = NULL;
    }
    return ret;
}

static uint8_t *_hook_alloc_closeby(uint8_t *target, uint32_t size)
{
    static uint8_t *last_ptr = NULL; MEMORY_BASIC_INFORMATION_CROSS mbi;

    if(last_ptr != NULL && last_ptr >= target - CLOSEBY_RANGE &&
            last_ptr < target + CLOSEBY_RANGE) {
        return _hook_alloc_closeby_ptr(&last_ptr, size);
    }

    for (uint8_t *addr = target - CLOSEBY_RANGE;
            addr < target + CLOSEBY_RANGE;
            addr += g_si.dwAllocationGranularity) {

        if(virtual_query(addr, &mbi) == FALSE || mbi.State != MEM_FREE) {
            continue;
        }

        if(virtual_alloc((void *) mbi.BaseAddress, g_si.dwPageSize,
                MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) == NULL) {
            continue;
        }

        memset((void *) mbi.BaseAddress, 0xcc, g_si.dwPageSize);
        last_ptr = (uint8_t *) mbi.BaseAddress;
        return _hook_alloc_closeby_ptr(&last_ptr, size);
    }
    return NULL;
}

int hook_create_jump(hook_t *h)
{
    uint8_t *addr = h->addr + h->skip;
    const uint8_t *target = (const uint8_t *) h->handler;
    int stub_used = h->stub_used - h->skip;

    NTSTATUS status =
        virtual_protect(addr, stub_used, PAGE_EXECUTE_READWRITE);
    if(NT_SUCCESS(status) == FALSE) {
        pipe("CRITICAL:Unable to change memory protection of %z!%z at "
            "0x%X %d to RWX (error code 0x%x)!",
            h->library, h->funcname, addr, stub_used, status);
        return -1;
    }

    // As the target is probably not close enough addr for a 32-bit relative
    // jump we allocate a separate page for an intermediate jump.
    uint8_t *closeby = _hook_alloc_closeby(addr, ASM_JUMP_SIZE);
    if(closeby == NULL) {
        pipe("CRITICAL:Unable to find closeby page for hooking!");
        return -1;
    }

    // Nop all used bytes out with int3's.
    memset(addr, 0xcc, stub_used);

    // Jump from the hooked address to our intermediate jump. The intermediate
    // jump address is within the 32-bit range a 32-bit jump can handle.
    asm_jump_32bit(addr, closeby);

    // Jump from the intermediate jump to the target address. This is a full
    // 64-bit jump.
    asm_jump(closeby, target);

    virtual_protect(addr, stub_used, PAGE_EXECUTE_READ);
    return 0;
}

#else

int hook_create_jump(hook_t *h)
{
    uint8_t *addr = h->addr + h->skip;
    const uint8_t *target = (const uint8_t *) h->handler;
    int stub_used = h->stub_used - h->skip;

    NTSTATUS status =
        virtual_protect(addr, stub_used, PAGE_EXECUTE_READWRITE);
    if(NT_SUCCESS(status) == FALSE) {
        pipe("CRITICAL:Unable to change memory protection of %z!%z at "
            "0x%X %d to RWX (error code 0x%x)!",
            h->library, h->funcname, addr, stub_used, status);
        return -1;
    }

    // Pad all used bytes out with int3's.
    memset(addr, 0xcc, stub_used);

    // Jump from the hooked address to the target address.
    asm_jump_32bit(addr, target);

    virtual_protect(addr, stub_used, PAGE_EXECUTE_READ);
    return 0;
}

#endif

#define MAXRESOLVECNT 50

static int _hook_determine_start(hook_t *h, uint8_t *addr)
{
    // Under Windows 7 some functions have been replaced by a function stub
    // which in turn calls the original function. E.g., a lot of functions
    // which originaly went through kernel32.dll now make a pass through
    // kernelbase.dll before reaching kernel32.dll.
    // We follow these jumps and add the regions to the list for unhook
    // detection.
    uint32_t count;

    for (count = 0; count < MAXRESOLVECNT; count++) {
        // jmp short imm8
        if(*addr == 0xeb) {
            unhook_detect_add_region(h->funcname, addr, addr, addr, 2);
            addr = addr + 2 + *(int8_t *)(addr + 1);
            continue;
        }

        // jmp dword [addr]
        if(*addr == 0xff && addr[1] == 0x25) {
            unhook_detect_add_region(h->funcname, addr, addr, addr, 6);

#if __x86_64__
            addr += *(uint32_t *)(addr + 2) + 6;
#else
            addr = *(uint8_t **)(addr + 2);
#endif

            unhook_detect_add_region(h->funcname, addr, addr, addr, 4);
            addr = *(uint8_t **) addr;
            continue;
        }

        // mov edi, edi ; push ebp ; mov ebp, esp ; pop ebp ; jmp short imm8
        if(memcmp(addr, "\x8b\xff\x55\x8b\xec\x5d\xeb", 7) == 0) {
            unhook_detect_add_region(h->funcname, addr, addr, addr, 8);
            addr = addr + 8 + *(int8_t *)(addr + 7);
            continue;
        }

        break;
    }

    // To make sure we don't enter an infinite loop.
    if(count == MAXRESOLVECNT) {
        return -1;
    }

    h->addr = addr;

    // If this function is a system call wrapper (and thus its first
    // instruction resembles "mov eax, imm32"), then skip the first
    // instruction.
    if(memcmp(h->funcname, "Nt", 2) == 0 && *addr == 0xb8) {
        h->skip += 5;
    }

    return 0;
}

int hook(hook_t *h)
{
    if(h->is_hooked != 0) {
        return 0;
    }

    HMODULE module_handle = GetModuleHandle(h->library);
    if(module_handle == NULL) return 0;

    FARPROC addr = GetProcAddress(module_handle, h->funcname);
    if(addr == NULL) {
        pipe("DEBUG:Error resolving function %z!%z.",
            h->library, h->funcname);
        return -1;
    }

    if(_hook_determine_start(h, (uint8_t *) addr) < 0) {
        pipe("CRITICAL:Error determining start of function %z!%z.",
            h->library, h->funcname);
        return -1;
    }

    static uint8_t *func_stubs = NULL;

    if(func_stubs == NULL) {
        func_stubs = virtual_alloc(NULL, sig_hook_count() * 64 + 8,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(func_stubs == NULL) {
            pipe("CRITICAL:Error allocating memory for hooks!");
            return -1;
        }

        // 8-byte align.
        func_stubs += 8 - ((uintptr_t) func_stubs & 7);
        memset(func_stubs, 0xcc, sig_hook_count() * 64);
    }

    h->func_stub = func_stubs;
    func_stubs += 64;

    *h->orig = (FARPROC) h->func_stub;

    // Create the original function stub.
    h->stub_used = hook_create_stub(h->func_stub,
        h->addr, ASM_JUMP_32BIT_SIZE + h->skip);
    if(h->stub_used < 0) {
        pipe("CRITICAL:Error creating function stub for %z!%z.",
            h->library, h->funcname);
        return -1;
    }

    uint8_t region_original[32];
    memcpy(region_original, h->addr, h->stub_used);

    // Patch the original function.
    if(hook_create_jump(h) < 0) {
        return -1;
    }

    unhook_detect_add_region(h->funcname, h->addr, region_original,
        h->addr, h->stub_used);

    if(h->initcb != NULL) {
        h->initcb(h);
    }

    h->is_hooked = 1;
    return 0;
}
