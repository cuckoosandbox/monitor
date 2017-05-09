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
#include "ole.h"
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

static int g_wmi_count = 0;
static int g_bits_count = 0;

static void _cb_hook(const char *library, void *module_handle)
{
    (void) module_handle;

    if(strcmp(library, "__wmi__") == 0) {
        g_wmi_count++;
    }
    if(strcmp(library, "__bits__") == 0) {
        g_bits_count++;
    }
}

static void _cb_unhook(const char *library, void *module_handle)
{
    (void) library; (void) module_handle;
}

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    misc_init2(&_cb_hook, &_cb_unhook);

    ole_enable_hooks(&our_CLSID_WbemAdministrativeLocator);
    assert(g_wmi_count == 1 && g_bits_count == 0);

    ole_enable_hooks(&our_CLSID_BackgroundCopyManager);
    assert(g_wmi_count == 1 && g_bits_count == 1);

    ole_enable_hooks(&our_IID_IUnknown);
    assert(g_wmi_count == 1 && g_bits_count == 1);

    ole_enable_hooks(&our_CLSID_BackgroundCopyManager25);
    assert(g_wmi_count == 1 && g_bits_count == 2);

    pipe("INFO:Test finished!");
    return 0;
}
