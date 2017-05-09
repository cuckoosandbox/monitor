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

#ifndef MONITOR_OLE_H
#define MONITOR_OLE_H

#include <wbemidl.h>

extern HRESULT (WINAPI *pCoCreateInstance)(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
    REFIID riid, LPVOID *ppv
);

extern CLSID our_CLSID_WbemAdministrativeLocator;
extern CLSID our_CLSID_WbemLocator;
extern CLSID our_CLSID_BackgroundCopyManager;
extern CLSID our_CLSID_BackgroundCopyManager15;
extern CLSID our_CLSID_BackgroundCopyManager20;
extern CLSID our_CLSID_BackgroundCopyManager25;
extern CLSID our_CLSID_BackgroundCopyManager30;
extern CLSID our_IID_IUnknown;
extern CLSID our_IID_IBackgroundCopyManager;

typedef struct _guid_libraries_t {
    const char *library;
    CLSID *guid;
} guid_libraries_t;

int init_co_create_instance();

#endif
