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

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "pipe.h"

// Tests very basic process following logic.

/// FINISH= yes
/// PIPE= yes

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

void inject(const char *filepath)
{
    char cmdline[MAX_PATH+MAX_PATH];
    STARTUPINFO si; PROCESS_INFORMATION pi;

    sprintf(cmdline, "\"%s\" \"World\"", filepath);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);

    assert(CreateProcess(filepath, cmdline, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi) != FALSE);

    Sleep(1000);

    assert(ResumeThread(pi.hThread) != (DWORD) -1);
}

void msgbox(const char *arg)
{
    MessageBox(NULL, arg, "Hello", 0);
}

int main(int argc, char *argv[])
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    if(argc == 1) {
        inject(argv[0]);
    }
    else {
        msgbox(argv[1]);
    }
    pipe("INFO:Test finished!");
    return 0;
}
