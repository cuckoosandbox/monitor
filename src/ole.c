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

#include <wbemidl.h>
#include <string.h>
#include "hooking.h"
#include "misc.h"
#include "ole.h"

HRESULT (WINAPI *pCoCreateInstance)(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
    REFIID riid, LPVOID *ppv
);

CLSID our_CLSID_WbemAdministrativeLocator = {
    0xcb8555cc, 0x9128, 0x11d1, {0xad,0x9b, 0x00,0xc0,0x4f,0xd8,0xfd,0xff},
};

CLSID our_CLSID_WbemLocator = {
    0x4590f811, 0x1d3a, 0x11d0, {0x89,0x1f, 0x00,0xaa,0x00,0x4b,0x2e,0x24},
};

CLSID our_CLSID_BackgroundCopyManager = {
    0x4991d34b, 0x80a1, 0x4291, {0x83,0xb6, 0x33,0x28,0x36,0x6b,0x90,0x97},
};

CLSID our_CLSID_BackgroundCopyManager15 = {
    0xf087771f, 0xd74f, 0x4c1a, {0xbb,0x8a, 0xe1,0x6a,0xca,0x91,0x24,0xea},
};

CLSID our_CLSID_BackgroundCopyManager20 = {
    0x6d18ad12, 0xbde3, 0x4393, {0xb3,0x11, 0x09,0x9c,0x34,0x6e,0x6d,0xf9},
};

CLSID our_CLSID_BackgroundCopyManager25 = {
    0x03ca98d6, 0xff5d, 0x49b8, {0xab,0xc6, 0x03,0xdd,0x84,0x12,0x70,0x20},
};

CLSID our_CLSID_BackgroundCopyManager30 = {
    0x659cdea7, 0x489e, 0x11d9, {0xa9,0xcd, 0x00,0x0d,0x56,0x96,0x52,0x51},
};

CLSID our_IID_IUnknown = {
    0x00000000, 0x0000, 0x0000, {0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46},
};

CLSID our_IID_IBackgroundCopyManager = {
    0x5ce34c0d, 0x0dc9, 0x4c1f, {0x89,0x7c, 0xda,0xa1,0xb7,0x8c,0xee,0x7c},
};

static guid_libraries_t g_libraries[] = {
    {"__wmi__", &our_CLSID_WbemLocator},
    {"__wmi__", &our_CLSID_WbemAdministrativeLocator},
    {"__bits__", &our_CLSID_BackgroundCopyManager},
    {"__bits__", &our_CLSID_BackgroundCopyManager15},
    {"__bits__", &our_CLSID_BackgroundCopyManager20},
    {"__bits__", &our_CLSID_BackgroundCopyManager25},
    {"__bits__", &our_CLSID_BackgroundCopyManager30},
    {NULL},
};

void ole_enable_hooks(REFCLSID clsid)
{
    for (guid_libraries_t *lib = g_libraries; lib->library != NULL; lib++) {
        if(memcmp(lib->guid, clsid, sizeof(CLSID)) == 0) {
            hook_library(lib->library, NULL);
            break;
        }
    }
}

int init_co_create_instance()
{
    if(pCoCreateInstance != NULL) {
        return 0;
    }

    HANDLE module_handle = GetModuleHandle("ole32");
    if(module_handle == NULL) {
        return -1;
    }

    *(FARPROC *) &pCoCreateInstance =
        GetProcAddress(module_handle, "CoCreateInstance");
    return 0;
}
