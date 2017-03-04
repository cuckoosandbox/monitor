/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2016-2017 Cuckoo Foundation.

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

/// PIPE= yes

#define _WIN32_WINNT 0x602
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

uint32_t print_tids(uint32_t process_identifier)
{
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        pipe("WARNING:Error getting snapshot handle to enumerate threads.");
        return 0;
    }

    THREADENTRY32 te; te.dwSize = sizeof(THREADENTRY32);
    if(Thread32First(snapshot_handle, &te) == FALSE) {
        pipe("WARNING:Error enumerating thread identifiers.");
        return 0;
    }

    uint32_t thread_identifier = 0;

    do {
        if(te.th32OwnerProcessID == process_identifier) {
            pipe("INFO:tid=%d", te.th32ThreadID);
        }
    } while (Thread32Next(snapshot_handle, &te) != FALSE);

    CloseHandle(snapshot_handle);
    return thread_identifier;
}

int main(int argc, char *argv[])
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    if(argc == 2) {
        pipe("INFO:THIS IS CHILD..");
        while (1) {
            Sleep(1000);
            pipe("INFO:CHILD STILL AVAILABLE");
        }
    }

    HANDLE job_handle = CreateJobObject(NULL, NULL);

    char cmdline[512];
    sprintf(cmdline, "\"%s\" is_job", argv[0]);

    STARTUPINFO si = {}; si.cb = sizeof(si); PROCESS_INFORMATION pi;
    assert(CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
        CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED | DETACHED_PROCESS,
        NULL, NULL, &si, &pi) != FALSE);

    pipe("INFO:before assign");
    print_tids(pi.dwProcessId);

    AssignProcessToJobObject(job_handle, pi.hProcess);

    pipe("INFO:after assign #1");
    print_tids(pi.dwProcessId);

    Sleep(1000);

    pipe("INFO:after assign #2");
    print_tids(pi.dwProcessId);

    ResumeThread(pi.hThread);

    pipe("INFO:after assign #3");
    print_tids(pi.dwProcessId);

    CloseHandle(job_handle);
    pipe("INFO:Test finished!");
}
