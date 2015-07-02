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
#include "assembly.h"
#include "hooking.h"
#include "pipe.h"
#include "symbol.h"

static uint8_t *memmem(
    uint8_t *haystack, uint32_t haylength,
    void *needle, uint32_t needlength,
    uint32_t *idx)
{
    uint32_t _idx = 0;

    if(idx == NULL) {
        idx = &_idx;
    }

    for (; *idx < haylength - needlength; *idx += 1) {
        if(memcmp(&haystack[*idx], needle, needlength) == 0) {
            return &haystack[*idx];
        }
    }
    return NULL;
}

#if __x86_64__

static uint8_t *_addr_colescript_compile(
    uint8_t *module_address, uintptr_t module_size, uintptr_t eval_code_addr)
{
    uint8_t *code_ptr = NULL;

    // Locate 'lea rax, "eval code"' instruction.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
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
        pipe("WARNING:COleScript::Compile error locating "
            "\"lea rax, 'eval code'\" instruction [aborting hook]");
        return NULL;
    }

    // Get the address passed along to the first call instruction.
    for (uint32_t idx = 0; idx < 20; idx++) {
        if(*code_ptr == 0xe8) {
            return code_ptr + *(int32_t *)(code_ptr + 1) + 5;
        }

        code_ptr += lde(code_ptr);
    }

    pipe("WARNING:COleScript::Compile error fetching address "
        "of the first call [aborting hook]");
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

uint8_t *hook_addrcb_COleScript_Compile(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    // Locate address of the "eval code" string.
    uint8_t *eval_code_addr = memmem(module_address, module_size,
        L"eval code", sizeof(L"eval code"), NULL);
    if(eval_code_addr == NULL) {
        pipe("WARNING:COleScript::Compile error locating 'eval code' "
            "string [aborting hook]");
        return NULL;
    }

    return _addr_colescript_compile(
        module_address, module_size, (uintptr_t) eval_code_addr);
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

uint8_t *hook_addrcb_CDocument_write(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    // Locate a possible address of the "\r\n" string.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        uint8_t *newline_addr = memmem(module_address, module_size,
            L"\r\n", sizeof(L"\r\n"), &idx);
        if(newline_addr == NULL) {
            break;
        }

        uint8_t *ret = _addr_cdocument_write(
            module_address, module_size, (uintptr_t) newline_addr);
        if(ret != NULL) {
            return ret;
        }
    }

    pipe("WARNING:CDocument::write error locating address [aborting hook]");
    return NULL;
}

uint8_t *hook_addrcb_CHyperlink_SetUrlComponent(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    // We are going to be looking for a sequence of instructions to find the
    // CHyperLink::SetUrlComponent function.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        // We look for a relative call followed immediately by a cmp reg, 7
        // instruction.
        if(module_address[idx] != 0xe8 || module_address[idx+5] != 0x83 ||
                ((module_address[idx+6] >> 3) & 7) != 7 ||
                module_address[idx+7] != 7) {
            continue;
        }

        // We then look for a mov [stack], 0x10000000 instruction followed by
        // a relative call instruction in the upcoming 256 bytes.
        uint8_t *ptr = &module_address[idx];
        while (ptr < &module_address[idx + 0x100]) {
            int32_t len = lde(ptr);

            // If found, set ptr to null and break.
            if(*ptr == 0xc7 && ptr[len] == 0xe8 &&
                    memcmp(&ptr[len-4], "\x00\x00\x00\x10", 4) == 0) {
                ptr = NULL;
                break;
            }

            ptr += len;
        }

        // If ptr was set to null then we found the function.
        if(ptr != NULL) {
            continue;
        }

        for (uint32_t jdx = 0; jdx < 256; jdx++) {
            // Look for three nop instructions.
            if(memcmp(&module_address[idx - jdx], "\x90\x90\x90", 3) == 0) {
                return &module_address[idx - jdx + 3];
            }
        }
    }

    return NULL;
}

uint8_t *hook_addrcb_CIFrameElement_CreateElement(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    // Locate the "IFRAME" string.
    uint8_t *iframe_addr = memmem(module_address, module_size,
        L"IFRAME", sizeof(L"IFRAME"), NULL);
    if(iframe_addr == NULL) {
        pipe("WARNING:CIFrameElement::CreateElement error locating "
            "'IFRAME' string [aborting hook]");
        return NULL;
    }

    // Find the cross-reference of the 'IFRAME' string.
    uint8_t *ret = memmem(module_address, module_size,
        &iframe_addr, sizeof(iframe_addr), NULL);
    if(ret == NULL) {
        pipe("WARNING:CIFrameElement::CreateElement error locating "
            "'IFRAME' string cross reference [aborting hook]");
        return NULL;
    }

    // Return the function pointer.
    return *(uint8_t **)(ret + 2 * sizeof(uintptr_t));
}

uint8_t *hook_addrcb_CWindow_AddTimeoutCode(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    // We're going on a long journey here. First we locate
    // CDoc::CRecalcHost::CompileExpression as that function uses the
    // unique L"return (" string.
    uint8_t *return_str_addr = memmem(module_address, module_size,
        L"return (", sizeof(L"return ("), NULL);
    if(return_str_addr == NULL) {
        pipe("WARNING:CWindow::AddTimeoutCode unable to locate 'return (' "
            "string [aborting hook]");
        return NULL;
    }

    uint8_t *compile_expression = NULL;

    for (uint32_t idx = 0; idx < module_size; idx++) {
        // Locate the 'lea rdx, "return ("' instruction.
        if(memmem(module_address, module_size,
                "\x48\x8d\x15", 3, &idx) == NULL) {
            break;
        }

        uint8_t *target = &module_address[idx] +
            *(int32_t *)(&module_address[idx] + 3) + 7;
        if(return_str_addr == target) {
            compile_expression = &module_address[idx];
            break;
        }
    }

    if(compile_expression == NULL) {
        pipe("WARNING:CWindow::AddTimeoutCode unable to locate correct "
            "'lea rdx, \"return (\"' instruction [aborting hook]");
        return NULL;
    }

    // Then we find the CScriptCollection::ConstructCode function call. We
    // look for a few flags to indicate that we're about to find this call,
    // namely, its parameters.
    // * A register has to be loaded with the address that points to a 32-bit
    //   zero floating point value.
    // * The r9d register has to be set to zero (xor r9d, r9d).
    // * The edx register has to be set to zero (xor edx, edx).
    uint8_t *construct_code = NULL, *addr = compile_expression;
    for (uint32_t idx = 0, state = 0; idx < 256; idx++) {
#if __x86_64__
        if((*addr == 0x48 || *addr == 0x4c) && addr[1] == 0x8d &&
                (addr[2] & 0xc7) == 0x05) {
            uint8_t *target = addr + *(int32_t *)(addr + 3) + 7;
            if(target >= module_address &&
                    target < module_address + module_size &&
                    *(uint32_t *) target == 0) {
                state |= 1;
            }
        }
        else if(*addr == 0x45 && addr[1] == 0x33 && addr[2] == 0xc9) {
            state |= 2;
        }
        else if(*addr == 0x33 && addr[1] == 0xd2) {
            state |= 4;
        }
        // We found the function.
        else if(*addr == 0xe8 && state == 7) {
            construct_code = addr + *(int32_t *)(addr + 1) + 5;
            break;
        }
#endif

        addr += lde(addr);
    }

    if(construct_code == NULL) {
        pipe("WARNING:CWindow::AddTimeoutCode unable to find ConstructCode "
            "function call [aborting hook]");
        return NULL;
    }

    FARPROC p_rtl_allocate_heap =
        GetProcAddress(GetModuleHandle("ntdll"), "RtlAllocateHeap");

    // We find all cross-references to the CScriptCollection::ConstructCode
    // function.
    for (uint32_t idx = 0; idx < module_size - 20; idx++) {
        uint8_t *addr = &module_address[idx];
        uint8_t *target = addr + *(int32_t *)(addr + 1) + 5;
        if(*addr != 0xe8 || target != construct_code) {
            continue;
        }

        // First go back to find the function start.
        uint8_t *start = NULL;
        for (uint32_t jdx = 0; jdx < 512; jdx++) {
            if(memcmp(addr - jdx, "\x90\x90\x90", 3) == 0) {
                addr = start = addr - jdx + 3;
                break;
            }
        }

        // Not this one!
        if(start == NULL) {
            continue;
        }

        // Does this function call HeapAlloc at the very start?
        for (uint32_t jdx = 0; jdx < 32; jdx++) {
#if __x86_64__
            target = addr + *(int32_t *)(addr + 2) + 6;
#endif
            if(*addr == 0xff && addr[1] == 0x15 &&
                    target >= module_address &&
                    target < module_address + module_size) {
                FARPROC fnaddr = *(FARPROC *) target;
                if(fnaddr == p_rtl_allocate_heap) {
                    return start;
                }
            }

            addr += lde(addr);
        }
    }

    pipe("WARNING:CWindow::AddTimeoutCode unable to find our function based "
        "on ConstructCode cross-references [aborting hook]");
    return NULL;
}

uint8_t *hook_addrcb_CScriptElement_put_src(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    uint8_t *diid_disphtmlscriptelement = memmem(module_address, module_size,
        "\x30\xf5\x50\x30\xb5\x98\xcf\x11\xbb\x82\x00\xaa\x00\xbd\xce\x0b",
        16, NULL);
    if(diid_disphtmlscriptelement == NULL) {
        pipe("WARNING:CScriptElement::put_src unable to find "
            "DIID_DispHTMLScriptElement [aborting hook]");
        return NULL;
    }

    uint8_t *addr_diid = memmem(module_address, module_size,
        &diid_disphtmlscriptelement, sizeof(diid_disphtmlscriptelement),
        NULL);
    if(addr_diid == NULL) {
        pipe("WARNING:CScriptElement::put_src unable to find cross-reference "
            "to DIID_DispHTMLScriptElement [aborting hook]");
        return NULL;
    }

    uint8_t *addr_addr_diid = memmem(module_address, module_size,
        &addr_diid, sizeof(addr_diid), NULL);
    if(addr_diid == NULL) {
        pipe("WARNING:CScriptElement::put_src unable to find cross-reference "
            "of cross-reference to DIID_DispHTMLScriptElement "
            "[aborting hook]");
        return NULL;
    }

    uint8_t **ihtml_script_element_vtable =
        *(uint8_t ***)(addr_addr_diid + sizeof(uintptr_t));
    if(ihtml_script_element_vtable == NULL) {
        pipe("WARNING:CScriptElement::put_src unable to find "
            "IHTMLScriptElement vtable [aborting hook]");
        return NULL;
    }

    return ihtml_script_element_vtable[7];
}

uint8_t *hook_addrcb_CElement_put_innerHTML(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

#if !__x86_64__
    return NULL;
#endif

    uint8_t *innerhtml_addr = memmem(module_address, module_size,
        L"innerHTML", sizeof(L"innerHTML"), NULL);
    if(innerhtml_addr == NULL) {
        pipe("WARNING:CElement::put_innerHTML unable to find 'innerHTML' "
            "string [aborting hook]");
        return NULL;
    }

    uint8_t *innerhtml_xref = memmem(module_address, module_size,
        &innerhtml_addr, sizeof(innerhtml_addr), NULL);
    if(innerhtml_xref == NULL) {
        pipe("WARNING:CElement::put_innerHTML unable to find 'innerHTML' "
            "string cross-reference [aborting hook]");
        return NULL;
    }

    uint8_t *propdesc_innerhtml = innerhtml_xref - sizeof(uintptr_t);
    for (uint32_t idx = 0; idx < module_size; idx++) {
        if(memmem(module_address, module_size,
                "\x4c\x8d\x0d", 3, &idx) == NULL) {
            pipe("WARNING:CElement::put_innerHTML unable to locate "
                "'lea r9, propdesc_innerHTML' instruction [aborting hook]");
            return NULL;
        }

        uint8_t *target = &module_address[idx] +
            *(int32_t *)(&module_address[idx] + 3) + 7;
        if(target != propdesc_innerhtml) {
            continue;
        }

        for (uint32_t jdx = 0; jdx < 256; jdx++) {
            if(memcmp(&module_address[idx - jdx], "\x90\x90\x90", 3) == 0) {
                return &module_address[idx - jdx + 3];
            }
        }
    }

    pipe("WARNING:CElement::put_innerHTML unable to locate function "
        "[aborting hook]");
    return NULL;
}

uint8_t *hook_addrcb_PRF(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

    uint8_t *master_secret_addr = memmem(module_address, module_size,
        "master secret", sizeof("master secret"), NULL);
    if(master_secret_addr == NULL) {
        pipe("WARNING:PRF unable to find 'master secret' "
            "string [aborting hook]");
        return NULL;
    }

#if __x86_64__
    for (uint32_t idx = 0; idx < module_size; idx++) {
        if(memmem(module_address, module_size,
                "\x48\x8d\x05", 3, &idx) == NULL) {
            break;
        }

        uint8_t *target = &module_address[idx] +
            *(int32_t *)(&module_address[idx] + 3) + 7;
        if(target != master_secret_addr) {
            continue;
        }

        // Look for a call instruction within the next few instructions.
        for (uint32_t jdx = 0; jdx < 8; jdx++) {
            if(module_address[idx] == 0xe8) {
                return asm_get_rel_call_target(&module_address[idx]);
            }

            idx += lde(&module_address[idx]);
        }
    }
#else
    uint8_t push_buf[5] = {0x68};
    *(uint8_t **)(push_buf + 1) = master_secret_addr;

    uint8_t *master_secret_xref = memmem(module_address, module_size,
        push_buf, sizeof(push_buf), NULL);
    if(master_secret_xref == NULL) {
        pipe("WARNING:PRF unable to locate the 'master secret' "
            "cross-reference instruction [aborting hook]");
        return NULL;
    }

    for (uint32_t idx = 0; idx < 8; idx++) {
        if(*master_secret_xref == 0xe8) {
            return asm_get_rel_call_target(master_secret_xref);
        }
        master_secret_xref += lde(master_secret_xref);
    }
#endif

    pipe("WARNING:PRF unable to locate the PRF function [aborting hook]");
    return NULL;
}

uint8_t *hook_addrcb_Ssl3GenerateKeyMaterial(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

    // TODO Look for "HHHHHHHH" and then look for the function that does not
    // reference the "HASH" string soon after.
    // The following is just a temporary solution.
    uint8_t *prf_addr = hook_addrcb_PRF(h, module_address, module_size);
    if((((uintptr_t) prf_addr) & 0xffff) == 0x4bc0) {
        return prf_addr + (0xe100 - 0x4bc0);
    }
    return NULL;
}
