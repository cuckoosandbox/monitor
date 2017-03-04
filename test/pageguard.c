/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2017 Cuckoo Foundation.

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

// Tests the page guard detection functionality.

// OPTIONS= human=0,pipe=cuckoo,mode=exploit,trigger=exefile

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "hooking.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "pipe.h"
#include "symbol.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

static void callback(const char *funcname, uintptr_t address, void *context)
{
    if(strcmp(funcname, "LoadLibraryW") == 0) {
        *(uintptr_t *) context = address;
    }
}

int main(int argc, char *argv[])
{
    (void) argc;

    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    hook_init(GetModuleHandle(NULL));
    assert(native_init() == 0);
    misc_init("hoi");

    symbol_init(GetModuleHandle(NULL));

    const uint8_t *module = (const uint8_t *) GetModuleHandle("kernel32");
    void *addr = NULL;

    // "Trigger" our file so that exploit mitigations are installed.
    fclose(fopen(argv[0], "rb"));

    if(module[0] == 'M' && module[1] == 'Z') {
        symbol_enumerate_module((HMODULE) module, &callback, &addr);
        assert(addr == GetProcAddress((HMODULE) module, "LoadLibraryW"));
    }

    uint32_t t = GetTickCount();
    for (uint32_t idx = 0; idx < 0x1000; idx++) {
        char ch = module[idx % 0x1000];
        assert(ch == (ch ^ 0x41 ^ 0x41));
    }
    // Under normal load this should take up to 5 to 10 seconds.
    assert(GetTickCount() - t < 20000);
    pipe("INFO:Test finished!");
    return 0;
}
