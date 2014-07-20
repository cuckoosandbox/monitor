#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "capstone/include/capstone.h"
#include "capstone/include/x86.h"
#include "hooking.h"
#include "ntapi.h"
#include "pipe.h"
#include "slist.h"

#define TLS_HOOK_INFO 0x44

extern const uint8_t *asm_tramp, *asm_guide, *asm_clean;
extern const uint32_t asm_tramp_size, asm_guide_size, asm_clean_size;

extern const uint32_t asm_tramp_hook_alloc_off;
extern const uint32_t asm_tramp_hook_handler_off;
extern const uint32_t asm_tramp_orig_func_stub_off;
extern const uint32_t asm_tramp_retaddr_off;
extern const uint32_t asm_tramp_retaddr_add_off;

extern const uint32_t asm_guide_orig_stub_off;
extern const uint32_t asm_guide_retaddr_add_off;
extern const uint32_t asm_guide_retaddr_pop_off;

extern const uint32_t asm_clean_retaddr_pop_off;

hook_info_t *hook_alloc()
{
    hook_info_t *ret = (hook_info_t *) calloc(1, sizeof(hook_info_t));
    slist_init(&ret->retaddr, 128);
    slist_init(&ret->eax, 128);
    writefsdword(TLS_HOOK_INFO, (uint32_t) ret);
    return ret;
}

hook_info_t *hook_info()
{
    hook_info_t *ret = (hook_info_t *) readfsdword(TLS_HOOK_INFO);
    if(ret == NULL) {
        ret = hook_alloc();
    }
    return ret;
}

void __stdcall hook_retaddr_add(uint32_t retaddr)
{
    hook_info_t *h = hook_info();
    slist_push(&h->retaddr, retaddr);
}

uint32_t __stdcall hook_retaddr_pop()
{
    hook_info_t *h = hook_info();
    return slist_pop(&h->retaddr);
}

void __stdcall hook_eax_add(uint32_t value)
{
    hook_info_t *h = hook_info();
    slist_push(&h->eax, value);
}

uint32_t __stdcall hook_eax_pop()
{
    hook_info_t *h = hook_info();
    return slist_pop(&h->eax);
}

int lde(const void *addr)
{
    static int capstone_init = 0; static csh capstone;

    if(capstone_init == 0) {
        cs_open(CS_ARCH_X86, CS_MODE_32, &capstone);
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

        // (Un)conditional jump or call with 32bit relative offset.
        if(*addr == 0xe9 || *addr == 0xe8 || (*addr == 0x0f &&
                addr[1] >= 0x80 && addr[1] < 0x90)) {

            // Copy the jmp or call instruction.
            // Unconditional jumps and calls consist of one byte.
            if(*addr == 0xe9 || *addr == 0xe8) {
                *tramp++ = *addr++;
            }
            // Conditional jumps consist of two bytes.
            else {
                *tramp++ = *addr++;
                *tramp++ = *addr++;
            }

            // When a jmp/call is performed, then the relative offset +
            // the instruction pointer + the size of the instruction is the
            // resulting address, so that's our target address.
            // As we have already written the first one or two bytes of the
            // instruction we only have the relative address left - four bytes
            // in total.
            uint32_t target = *(uint32_t *) addr + 4 + (uint32_t) addr;
            addr += 4;

            // We have already copied the instruction opcode(s) itself so we
            // just have to calculate the relative address now.
            *(uint32_t *) tramp = target - (uint32_t) tramp - 4;
            tramp += 4;

            // Because an unconditional jump denotes the end of a basic block
            // we will return failure if we have not yet processed enough room
            // to store our hook code.
            if(tramp[-5] == 0xe9 && len > 0) return -1;
        }
        // (Un)conditional jump with 8bit relative offset.
        else if(*addr == 0xeb || (*addr >= 0x70 && *addr < 0x80)) {

            // Same rules apply as with the 32bit relative offsets, except
            // for the fact that both conditional and unconditional 8bit
            // relative jumps take only one byte for the opcode.

            // We translate the 8-bit branch into a 32-bit one.
            if(*addr == 0xeb) {
                *tramp++ = 0xe9;
            }
            else {
                // Hex representation of the two types of 32bit jumps;
                // 8bit relative conditional jumps:     70..80
                // 32bit relative conditional jumps: 0f 80..90
                // Thus we have to add 0x10 to the opcode of 8bit relative
                // offset jump to obtain the 32bit relative offset jump
                // opcode.
                *tramp++ = 0x0f;
                *tramp++ = *addr + 0x10;
            }

            addr++;

            // 8bit relative offset - we have to sign-extend it, by casting it
            // as signed char, in order to calculate the correct address.
            uint32_t target = (uint32_t) addr + 1 + *(signed char *) addr;

            // Calculate the relative address.
            *(uint32_t *) tramp = target - (uint32_t) tramp - 4;
            tramp += 4;

            // Again, check the length as this is the end of the basic block.
            if(*addr == 0xeb && len > 0) return -1;

            addr++;
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
    *tramp++ = 0xe9;
    *(uint32_t *) tramp = (uint32_t) addr - (uint32_t) tramp - 4;
    return addr - base_addr;
}

int hook_create_jump(uint8_t *addr, const uint8_t *target, int stub_used)
{
    unsigned long old_protect;

    if(VirtualProtect(addr, stub_used, PAGE_EXECUTE_READWRITE,
            &old_protect) == FALSE) {
        return -1;
    }

    // Nop all used bytes out with int3's.
    memset(addr, 0xcc, stub_used);

    *addr = 0xe9;
    *(uint32_t *)(addr + 1) = target - addr - 5;

    VirtualProtect(addr, stub_used, old_protect, &old_protect);
    return 0;
}

#define PATCH(buf, off, value) \
    *(uint32_t *)(buf + off) = (uint32_t) value

int hook2(hook_t *h)
{
    HMODULE module_handle = GetModuleHandle(h->library);
    if(module_handle == NULL) return 0;

    uint8_t *addr = (uint8_t *) GetProcAddress(module_handle, h->funcname);
    if(addr == NULL) {
        pipe("CRITICAL:Error resolving function %z->%z!",
            h->library, h->funcname);
        return -1;
    }

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

    hd->trampoline = hd->_mem;
    hd->guide = hd->trampoline + 16 + asm_tramp_size;
    hd->clean = hd->guide + 16 + asm_guide_size;
    hd->func_stub = hd->clean + 16 + asm_clean_size;
    *h->orig = (FARPROC) hd->guide;

    // Create the original function stub.
    int stub_used = hook_create_stub(hd->func_stub, addr, 5);
    if(stub_used < 0) {
        pipe("CRITICAL:Error creating function stub for %z!", h->funcname);
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

    // Patch the original function.
    if(hook_create_jump(addr, hd->trampoline, stub_used) < 0) {
        pipe("CRITICIAL:Error creating function jump for %z!", h->funcname);
        return -1;
    }
    return 0;
}

int hook(const char *library, const char *funcname,
    FARPROC handler, FARPROC *orig)
{
    hook_t h;
    h.library = library;
    h.funcname = funcname;
    h.handler = handler;
    h.orig = orig;
    return hook2(&h);
}
