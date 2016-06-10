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

#include <wbemidl.h>
#include "hooking.h"
#include "misc.h"
#include "pipe.h"

static CLSID our_CLSID_WbemAdministrativeLocator = {
    0xcb8555cc, 0x9128, 0x11d1, {0xad,0x9b, 0x00,0xc0,0x4f,0xd8,0xfd,0xff},
};

static CLSID our_CLSID_WbemLocator = {
    0x4590f811, 0x1d3a, 0x11d0, {0x89,0x1f, 0x00,0xaa,0x00,0x4b,0x2e,0x24},
};

static CLSID our_IID_IUnknown = {
    0x00000000, 0x0000, 0x0000, {0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46},
};

static HRESULT (WINAPI *pCoCreateInstance)(REFCLSID rclsid,
    LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);

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

static int _locate_wbem_services(
    hook_t *h, IWbemLocator **wbem_locator, IWbemServices **wbem_services
)
{
    h->is_hooked = 1;

    if(init_co_create_instance() < 0) {
        return -1;
    }

    HRESULT res = pCoCreateInstance(&our_CLSID_WbemLocator, NULL,
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, &our_IID_IUnknown,
        (void **) wbem_locator);
    if(res == CO_E_NOTINITIALIZED) {
        h->is_hooked = 0;
        return -1;
    }
    if(SUCCEEDED(res) == FALSE) {
        pipe("WARNING:Error creating IWBemLocator instance error=0x%x "
            "[aborting hook %z]", res, h->funcname);
        h->is_hooked = 0;
        return -1;
    }

    if(SUCCEEDED((*wbem_locator)->lpVtbl->ConnectServer(*wbem_locator,
            L"root\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL,
            wbem_services)) == FALSE) {
        pipe("WARNING:Error connecting to IWBemLocator to fetch "
            "IWbemServices instance [aborting hook %z]", h->funcname);
        (*wbem_locator)->lpVtbl->Release(*wbem_locator);
        h->is_hooked = 0;
        return -1;
    }

    return 0;
}

uint8_t *hook_addrcb_IWbemServices_ExecQuery(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) module_address; (void) module_size;

    IWbemLocator *wbem_locator = NULL; IWbemServices *wbem_services;
    if(_locate_wbem_services(h, &wbem_locator, &wbem_services) < 0) {
        return NULL;
    }

    uint8_t *ret = (uint8_t *) wbem_services->lpVtbl->ExecQuery;

    wbem_locator->lpVtbl->Release(wbem_locator);
    wbem_services->lpVtbl->Release(wbem_services);
    return ret;
}

uint8_t *hook_addrcb_IWbemServices_ExecQueryAsync(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) module_address; (void) module_size;

    IWbemLocator *wbem_locator = NULL; IWbemServices *wbem_services = NULL;
    if(_locate_wbem_services(h, &wbem_locator, &wbem_services) < 0) {
        return NULL;
    }

    uint8_t *ret = (uint8_t *) wbem_services->lpVtbl->ExecQueryAsync;

    wbem_locator->lpVtbl->Release(wbem_locator);
    wbem_services->lpVtbl->Release(wbem_services);
    return ret;
}

uint8_t *hook_addrcb_IWbemServices_ExecMethod(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) module_address; (void) module_size;

    IWbemLocator *wbem_locator = NULL; IWbemServices *wbem_services = NULL;
    if(_locate_wbem_services(h, &wbem_locator, &wbem_services) < 0) {
        return NULL;
    }

    uint8_t *ret = (uint8_t *) wbem_services->lpVtbl->ExecMethod;

    wbem_locator->lpVtbl->Release(wbem_locator);
    wbem_services->lpVtbl->Release(wbem_services);
    return ret;
}

uint8_t *hook_addrcb_IWbemServices_ExecMethodAsync(hook_t *h,
    uint8_t *module_address, uint32_t module_size)
{
    (void) module_address; (void) module_size;

    IWbemLocator *wbem_locator = NULL; IWbemServices *wbem_services = NULL;
    if(_locate_wbem_services(h, &wbem_locator, &wbem_services) < 0) {
        return NULL;
    }

    uint8_t *ret = (uint8_t *) wbem_services->lpVtbl->ExecMethodAsync;

    wbem_locator->lpVtbl->Release(wbem_locator);
    wbem_services->lpVtbl->Release(wbem_services);
    return ret;
}

int wmi_win32_process_create_pre(
    IWbemServices *services, IWbemClassObject *args, uint32_t *creation_flags
) {
    VARIANT vt; HRESULT hr; IWbemClassObject *si = NULL;

    vt.vt = VT_EMPTY;
    hr = args->lpVtbl->Get(
        args, L"ProcessStartupInformation", 0, &vt, NULL, NULL
    );
    if(SUCCEEDED(hr) == FALSE) {
        pipe("WARNING:Error getting ProcessStartupInformation member of "
            "Win32_Process::Create parameters.");
        return -1;
    }

    if(vt.vt == VT_NULL) {
        hr = services->lpVtbl->GetObject(
            services, L"Win32_ProcessStartup", 0, NULL, &si, NULL
        );
        if(SUCCEEDED(hr) == FALSE) {
            pipe("WARNING:Error creating ProcessStartupInformation object "
                "to instrument child process execution.");
            return -1;
        }
    }
    else if(vt.vt == VT_UNKNOWN) {
        si = vt.byref;
    }

    if(si == NULL) {
        pipe("WARNING:StartupInfo is none, this should never happen.");
        return -1;
    }

    vt.vt = VT_EMPTY;
    si->lpVtbl->Get(si, L"CreateFlags", 0, &vt, NULL, NULL);
    *creation_flags = vt.vt == VT_I4 ? vt.uintVal : 0;

    vt.vt = VT_I4;
    vt.uintVal = *creation_flags | CREATE_SUSPENDED;
    hr = si->lpVtbl->Put(si, L"CreateFlags", 0, &vt, 0);
    if(SUCCEEDED(hr) == FALSE) {
        pipe("WARNING:Error updating Win32_ProcessStartup::CreateFlags.");
        return -1;
    }

    vt.vt = VT_UNKNOWN; vt.byref = si;
    hr = args->lpVtbl->Put(args, L"ProcessStartupInformation", 0, &vt, 0);
    if(SUCCEEDED(hr) == FALSE) {
        pipe("WARNING:Error updating "
            "Win32_Process::Create::ProcessStartupInformation.");
        return -1;
    }
    return 0;
}

void ole_enable_hooks(REFCLSID clsid)
{
    if(memcmp(clsid, &our_CLSID_WbemLocator, sizeof(CLSID)) == 0) {
        hook_library("__wmi__", NULL);
    }

    if(memcmp(clsid, &our_CLSID_WbemAdministrativeLocator,
            sizeof(CLSID)) == 0) {
        hook_library("__wmi__", NULL);
    }
}
