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

// This program demonstrates the case where malware closes all open handles
// therefore also closing our log pipe handle. We handle this by reopening
// the pipe handle. The logs for this analysis should show both MessageBoxA()
// calls or otherwise something is going wrong.

/// OBJECTS=

#include <stdio.h>
#include <stdint.h>
#include <windows.h>

int main()
{
    MessageBox(NULL, "Hello World", "Before", 0);

    // Just kill off all open handles in this process. Chances are this will
    // break other stuff as well, but at the very least the pipe log handle
    // will be closed as well.
    for (uintptr_t idx = 0; idx < 10000; idx += 4) {
        CloseHandle((HANDLE) idx);
    }

    MessageBox(NULL, "Hello World", "After", 0);
    return 0;
}
