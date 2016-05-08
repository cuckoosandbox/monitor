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

/// OPTIONS= free=yes,pipe=cuckoo

#include <stdio.h>
#include <windows.h>
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    FARPROC pObtainUserAgentString =
        GetProcAddress(LoadLibrary("urlmon"), "ObtainUserAgentString");

    char buf[512]; DWORD size = sizeof(buf);
    assert(pObtainUserAgentString(0, buf, &size) == NOERROR);
    assert(strncmp(buf, "Mozilla", 7) == 0);
}
