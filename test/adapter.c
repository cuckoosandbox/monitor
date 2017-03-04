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

// Shows the GetAdaptersInfo() entry in the logs. Before the changes to being
// able to hook recursively loaded DLLs, calls to GetAdaptersInfo() and
// similar would not show up, rendering their hooks useless.
// That is, when calling LoadLibrary/LdrLoadDll on test-adapter.dll, the
// imported dll iphlpapi.dll will not be loaded through LoadLibrary/LdrLoadDll
// but instead through an internal method, and thus we would not be updated
// about it being loaded, and thus we would not be able to place hooks on it.

/// EXTENSION= dll
/// CFLAGS= -shared -static
/// LDFLAGS += -liphlpapi
/// OBJECTS=

#include <winsock2.h>
#include <iphlpapi.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) dwReason; (void) lpReserved;

    GetAdaptersInfo(NULL, NULL);
    return TRUE;
}
