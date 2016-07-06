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
#include <oaidl.h>
#include "assembly.h"
#include "log.h"
#include "hooking.h"
#include "misc.h"
#include "pipe.h"

static funcoff_t _vbe6_StringConcat[] = {
    {0x45187577, 0x1fbd84, 0},
    {0, 0, 0},
};

// We should probably rename this one to rtcCreateObject2.
static funcoff_t _vbe6_CreateObject[] = {
    {0x45187577, 0x1f98a1, 0},
    {0, 0, 0},
};

// We should probably rename this one to rtcGetObject.
static funcoff_t _vbe6_GetObject[] = {
    {0x45187577, 0x1f9baf, 0},
    {0, 0, 0},
};

// Object method to call Invoke function.
static funcoff_t _vbe6_Invoke[] = {
    {0x45187577, 0x1f92d4, 0},
    {0, 0, 0},
};

// Object method to call GetIDsFromNames function.
static funcoff_t _vbe6_GetIDFromName[] = {
    {0x45187577, 0x22c67f, 0},
    {0, 0, 0},
};

// Object method to call CallByName function.
static funcoff_t _vbe6_CallByName[] = {
    {0x45187577, 0x1cbb8a, 0},
    {0, 0, 0},
};

// We should probably rename this one to rtcShell.
static funcoff_t _vbe6_Shell[] = {
    {0x45187577, 0x167c0e, 0},
    {0, 0, 0},
};

static funcoff_t _vbe6_Import[] = {
    {0x45187577, 0x3aba, 0},
    {0, 0, 0},
};

static funcoff_t _vbe6_Open[] = {
    {0x45187577, 0x1a2897, 0},
    {0, 0, 0},
};

static funcoff_t _vbe6_Print[] = {
    {0x45187577, 0x1a32d3, 0},
    {0, 0, 0},
};

static funcoff_t _vbe6_Close[] = {
    {0x45187577, 0x1a2d94, 0},
    {0, 0, 0},
};

static mod2funcoff_t _vbe6[] = {
    {"vbe6_StringConcat", _vbe6_StringConcat},
    {"vbe6_CreateObject", _vbe6_CreateObject},
    {"vbe6_GetObject", _vbe6_GetObject},
    {"vbe6_Invoke", _vbe6_Invoke},
    {"vbe6_GetIDFromName", _vbe6_GetIDFromName},
    {"vbe6_CallByName", _vbe6_CallByName},
    {"vbe6_Shell", _vbe6_Shell},
    {"vbe6_Import", _vbe6_Import},
    {"vbe6_Open", _vbe6_Open},
    {"vbe6_Print", _vbe6_Print},
    {"vbe6_Close", _vbe6_Close},
    {NULL, NULL},
};

uint8_t *hook_modulecb_vbe6(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    h->addr = module_addr_timestamp_mod(
        module_address, module_size, _vbe6, h->funcname, &h->cconv
    );
    return h->addr;
}

int vbe6_invoke_extract_args(uint8_t *addr, bson *b)
{
    // TODO Make sure this is correct as it probably is not the case for all
    // invocations of this function.
    uint32_t count = *(uint32_t *)(addr + 8);
    const VARIANT *va = *(const VARIANT **) addr;

    // There are no arguments.
    if(count == 0 || va == NULL) {
        return 0;
    }

    if(count >= 16) {
        pipe(
            "WARNING:Incorrect SAFEARRAY length found for "
            "vbe6_Invoke, skipping hook."
        );
        return -1;
    }

    char index[8];
    for (uint32_t idx = 0; idx < count; idx++) {
        const VARIANT *v = &va[count - idx - 1];
        our_snprintf(index, sizeof(index), "%d", idx);
        variant_to_bson(b, index, v, NULL);
    }

    return 0;
}

static wchar_t *g_funcname;

void vbe6_set_funcname(const wchar_t *funcname)
{
    g_funcname = our_wcsdup(funcname);
}

wchar_t *vbe6_get_funcname()
{
    wchar_t *ret = g_funcname;
    g_funcname = NULL;
    return ret;
}
