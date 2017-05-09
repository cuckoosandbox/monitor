/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2017 Cuckoo Foundation.

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

/// FINISH= yes
/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include "assembly.h"
#include "config.h"
#include "hooking.h"
#include "misc.h"
#include "native.h"
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

static uint8_t *_h_fallthrough_addrcb(
    hook_t *h, uint8_t *module_handle, uint32_t module_size)
{
    (void) h; (void) module_handle; (void) module_size;
    return NULL;
}

static uint8_t *_h2_addrcb(
    hook_t *h, uint8_t *module_handle, uint32_t module_size)
{
    (void) h; (void) module_handle; (void) module_size;
    return NULL;
}

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    copy_init();
    hook_init(GetModuleHandle(NULL));
    assert(native_init() == 0);
    misc_init("hoi");

    // Unit test against invalid fallthrough introduced in
    // f45da70b94d068fa12c821f46e4c49f8ce241289. Before the latest patch the
    // if(h->addr == NULL) would fail to succeed due to the resolve prune
    // thing being set. This may be demonstrated by having the later
    // GetProcAddress resolve the address of another function.
    hook_t h_fallthrough = {
        .module_handle = GetModuleHandle("kernel32"),
        .funcname = "CreateFileA",
        .library = NULL,
        .addr = NULL,
        .addrcb = &_h_fallthrough_addrcb,
        .report = HOOK_PRUNE_RESOLVERR,
    };
    assert(hook_resolve(&h_fallthrough) < 0);
    assert(h_fallthrough.addr == NULL);

    // "address callback" for "__wmi__" etc.
    hook_t h1 = {
        .module_handle = NULL,
        .library = L"__wmi__",
    };
    assert(hook_resolve(&h1) == 0);
    assert(h1.module_handle == NULL);

    // Failure when the address hook returns a nullptr.
    hook_t h2 = {
        .module_handle = NULL,
        .library = NULL,
        .addr = NULL,
        .addrcb = &_h2_addrcb,
    };
    assert(hook_resolve(&h2) < 0);
    assert(h2.addr == NULL);

    hook_t h3 = {
        .type = 999,
        .module_handle = GetModuleHandle("kernel32"),
        .funcname = "CreateProcessA",
        .addrcb = NULL,
    };
    assert(hook_resolve(&h3) == 1);
    assert(h3.addr == (uint8_t *) GetProcAddress(
        GetModuleHandle("kernel32"), "CreateProcessA"
    ));

    pipe("INFO:Test finished!");
    return 0;
}
