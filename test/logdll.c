/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2015-2017 Cuckoo Foundation.

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

// Tests whether function calls within DllMain are logged as these happen
// while inside the LdrLoadDll hook. Since a recent commit they are,
// naturally. Same goes for the exported function, although those were already
// logged successfully.
// The report should show two calls to MessageBoxTimeoutA.
// OPTIONS += function=exported_function

/// CFLAGS += -shared
/// EXTENSION = dll
/// OBJECTS =

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

__declspec(dllexport) void exported_function()
{
    MessageBox(NULL, "Exported Function", "Hello World", 0);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) dwReason; (void) lpReserved;

    if(dwReason == DLL_PROCESS_ATTACH) {
        MessageBox(NULL, "DllMain", "Hello World", 0);
    }
    return TRUE;
}
