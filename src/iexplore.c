/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2015-2018 Cuckoo Foundation.

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
#include "bson.h"
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "pipe.h"
#include "symbol.h"
#include "utf8.h"

void chtmtag_attrs(const void *chtmtag, bson *b)
{
#if !__x86_64__
    return;
#endif

    uint16_t count = *((const uint16_t *) chtmtag + 1);
    const wchar_t **ptr = (const wchar_t **)((const uint8_t *) chtmtag + 32);

    while (count-- != 0) {
        const wchar_t *key = ptr[0];
        uintptr_t keylen = (uintptr_t) ptr[1];
        const wchar_t *value = ptr[2];
        uintptr_t valuelen = (uintptr_t) ptr[3];

        char *utf8key = utf8_wstring(key, keylen);
        char *utf8val = utf8_wstring(value, valuelen);
        uint32_t utf8vallen = *(uint32_t *) utf8val;

        bson_append_binary(b, utf8key+4, BSON_BIN_BINARY,
            utf8val+4, utf8vallen);
        mem_free(utf8val);

        ptr += 40 / sizeof(uintptr_t);
    }
}

static FARPROC _var_getvalue;

static funcoff_t _var_getvalue_ts[] = {
    {0x4ce7c6df, 0x107e0, 0},
    {0, 0, 0},
};

static funcoff_t _CDocument_write[] = {
    {0x4ce7c7f0, 0x190400, 0},
    {0, 0, 0},
};

static funcoff_t _CHyperlink_SetUrlComponent[] = {
    {0x4ce7c7f0, 0x47b8f0, 0},
    {0, 0, 0},
};

static funcoff_t _CIFrameElement_CreateElement[] = {
    {0x4ce7c7f0, 0x467ed0, 0},
    {0, 0, 0},
};

static funcoff_t _CWindow_AddTimeoutCode[] = {
    {0x4ce7c7f0, 0x1dc300, 0},
    {0, 0, 0},
};

static funcoff_t _CScriptElement_put_src[] = {
    {0x4ce7c7f0, 0x4742a0, 0},
    {0, 0, 0},
};

static funcoff_t _CElement_put_innerHTML[] = {
    {0x4ce7c7f0, 0x1bbe90, 0},
    {0, 0, 0},
};

static funcoff_t _CImgElement_put_src[] = {
    {0x4ce7c7f0, 0x4158e0, 0},
    {0, 0, 0},
};

static mod2funcoff_t _mshtml[] = {
    {"CDocument_write", _CDocument_write},
    {"CHyperlink_SetUrlComponent", _CHyperlink_SetUrlComponent},
    {"CIFrameElement_CreateElement", _CIFrameElement_CreateElement},
    {"CWindow_AddTimeoutCode", _CWindow_AddTimeoutCode},
    {"CScriptElement_put_src", _CScriptElement_put_src},
    {"CElement_put_innerHTML", _CElement_put_innerHTML},
    {"CImgElement_put_src", _CImgElement_put_src},
    {NULL, NULL},
};

static funcoff_t _PRF[] = {
    {0x4a5bdfd4, 0x4bc0, 0},
    {0x4a5bda79, 0x81d5, 0},
    {0, 0, 0},
};

static funcoff_t _Ssl3GenerateKeyMaterial[] = {
    {0x4a5bdfd4, 0xe100, 0},
    {0x4a5bda79, 0x255be, 0},
    {0, 0, 0},
};

static mod2funcoff_t _ncrypt[] = {
    {"PRF", _PRF},
    {"Ssl3GenerateKeyMaterial", _Ssl3GenerateKeyMaterial},
    {NULL, NULL},
};

VAR *iexplore_var_getvalue(VAR *value, void *session)
{
    uintptr_t out;
    _var_getvalue(value, session, &value, &out, 0);
    return value;
}

uint8_t *hook_modulecb_mshtml(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    h->addr = module_addr_timestamp_mod(
        module_address, module_size, _mshtml, h->funcname, &h->cconv
    );
    return h->addr;
}

uint8_t *hook_modulecb_ncrypt(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    h->addr = module_addr_timestamp_mod(
        module_address, module_size, _ncrypt, h->funcname, &h->cconv
    );
    return h->addr;
}

void jscript_init(hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h;

    _var_getvalue = (FARPROC) module_addr_timestamp(
        module_address, module_size, _var_getvalue_ts, NULL
    );
}
