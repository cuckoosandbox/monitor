/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2016 Cuckoo Foundation.

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

static funcoff_t _pdf_eval[] = {
    {0x4850e6cb, 0xbb4ab, 0},
    {0, 0, 0},
};

static funcoff_t _pdf_unescape[] = {
    {0x4850e6cb, 0xbcc83, 0},
    {0, 0, 0},
};

static mod2funcoff_t _pdf[] = {
    {"pdf_eval", _pdf_eval},
    {"pdf_unescape", _pdf_unescape},
    {NULL, NULL},
};

uint8_t *hook_modulecb_escript_api(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    h->addr = module_addr_timestamp_mod(
        module_address, module_size, _pdf, h->funcname, &h->cconv
    );
    return h->addr;
}
