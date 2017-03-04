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

/// MODES=winxp win7x64
/// OBJECTS=

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>

static uint8_t shellcode[] = {
#if __x86_64__
    0x6a, 0x00,                             // push 0
    0xff, 0x35, 128-8, 0x00, 0x00, 0x00,    // push address
    0xff, 0x35, 256-14, 0x00, 0x00, 0x00,   // push address2
    0x6a, 0x00,                             // push 0
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, addr
    0xff, 0xd0,                             // call rax
    0xc3,                                   // retn
#else
    0x6a, 0x00,                             // push 0
    0x68, 0x00, 0x00, 0x00, 0x00,           // push address
    0x68, 0x00, 0x00, 0x00, 0x00,           // push address2
    0x6a, 0x00,                             // push 0
    0xb8, 0x00, 0x00, 0x00, 0x00,           // mov eax, addr
    0xff, 0xd0,                             // call eax
    0xc2, 0x04, 0x00,                       // retn 4
#endif
};

uint32_t pid_from_process_name(const char *process_name)
{
    PROCESSENTRY32 row; HANDLE snapshot_handle;

    snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Error obtaining snapshot handle: %ld\n",
            GetLastError());
        exit(1);
    }

    row.dwSize = sizeof(row);
    if(Process32First(snapshot_handle, &row) == FALSE) {
        fprintf(stderr, "[-] Error enumerating the first process: %ld\n",
            GetLastError());
        exit(1);
    }

    do {
        if(stricmp(row.szExeFile, process_name) == 0) {
            CloseHandle(snapshot_handle);
            return row.th32ProcessID;
        }
    } while (Process32Next(snapshot_handle, &row) != FALSE);

    CloseHandle(snapshot_handle);

    fprintf(stderr, "[-] Error finding process by name: %s\n", process_name);
    exit(1);
}

int main()
{
    uint32_t pid = pid_from_process_name("explorer.exe");
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    uint8_t *addr = (uint8_t *) VirtualAllocEx(process_handle, NULL, 0x1000,
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    uintptr_t messagebox_addr = (uintptr_t)
        GetProcAddress(LoadLibrary("user32.dll"), "MessageBoxA");

    static uint8_t buf[0x1000]; SIZE_T bytes_written;

    memcpy(buf, shellcode, sizeof(shellcode));

#if __x86_64__
    *(uintptr_t *) &buf[18] = messagebox_addr;
#else
    *(uint32_t *) &buf[3] = (uint32_t) addr + 128;
    *(uint32_t *) &buf[8] = (uint32_t) addr + 256;
    *(uint32_t *) &buf[15] = messagebox_addr;
#endif

    strcpy((char *) buf + 128, "World");
    strcpy((char *) buf + 256, "Hello");

    WriteProcessMemory(process_handle, addr, buf, sizeof(buf),
        &bytes_written);

    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0,
        (LPTHREAD_START_ROUTINE) addr, NULL, 0, NULL);

    CloseHandle(thread_handle);
    CloseHandle(process_handle);
    return 0;
}
