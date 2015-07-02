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

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>

static BOOL (WINAPI *pIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);

uint32_t pid_from_process_name(const wchar_t *process_name)
{
    PROCESSENTRY32W row; HANDLE snapshot_handle;

    snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Error obtaining snapshot handle: %ld\n",
            GetLastError());
        exit(1);
    }

    row.dwSize = sizeof(row);
    if(Process32FirstW(snapshot_handle, &row) == FALSE) {
        fprintf(stderr, "[-] Error enumerating the first process: %ld\n",
            GetLastError());
        exit(1);
    }

    do {
        if(wcsicmp(row.szExeFile, process_name) == 0) {
            CloseHandle(snapshot_handle);
            return row.th32ProcessID;
        }
    } while (Process32NextW(snapshot_handle, &row) != FALSE);

    CloseHandle(snapshot_handle);

    fprintf(stderr, "[-] Error finding process by name: %S\n", process_name);
    exit(1);
}

HANDLE open_process(uint32_t pid)
{
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(process_handle == NULL) {
        fprintf(stderr, "[-] Error getting access to process: %ld!\n",
            GetLastError());
        exit(1);
    }

    return process_handle;
}

static int determine_process_identifier(uint32_t pid)
{
    HANDLE process_handle = open_process(pid);
    BOOL wow64_process; SYSTEM_INFO si;

    GetNativeSystemInfo(&si);

    // If the IsWow64Process function doesn't exist then this is an older
    // 32-bit Windows version.
    if(pIsWow64Process == NULL) {
        printf("32");
    }
    // If it fails then we emit an error.
    else if(pIsWow64Process(process_handle, &wow64_process) == FALSE) {
        fprintf(stderr, "Error obtaining wow64 process status\n");
        return 1;
    }

    // This is a 32-bit machine.
    if(si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        printf("32");
        return 0;
    }

    // TODO It is also possible to run 32-bit Windows on a 64-bit machine.
    if(si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        fprintf(stderr, "Invalid processor architecture\n");
        return 1;
    }

    printf(wow64_process == FALSE ? "64" : "32");
    return 0;
}

static int determine_pe_file(const wchar_t *filepath)
{
    FILE *fp = _wfopen(filepath, L"rb");
    if(fp == NULL) {
        fprintf(stderr, "Error opening filepath\n");
        return 1;
    }

    static uint8_t buf[0x2000];

    fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) buf;
    if(image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Invalid DOS file\n");
        return 1;
    }

    IMAGE_NT_HEADERS *image_nt_headers =
        (IMAGE_NT_HEADERS *)(buf + image_dos_header->e_lfanew);
    if(image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE file\n");
        return 1;
    }

    switch (image_nt_headers->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
        printf("32");
        return 0;

    case IMAGE_FILE_MACHINE_AMD64:
        printf("64");
        return 0;

    default:
        fprintf(stderr, "Invalid PE file: not a 32-bit or 64-bit\n");
        return 1;
    }
}

int main()
{
    LPWSTR *argv; int argc;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if(argv == NULL) {
        printf("Error parsing commandline options!\n");
        return 1;
    }

    if(argc != 3) {
        printf("Usage: %S <option..>\n", argv[0]);
        printf("Options:\n");
        printf("  -p --pid          <pid>\n");
        printf("  -n --process-name <process-name>\n");
        printf("  -f --file         <path>\n");
        printf("\n");
        printf("Examples:\n");
        printf("%S -p 1234\n", argv[0]);
        printf("%S -n lsass.exe\n", argv[0]);
        printf("%S -f %S\n", argv[0], argv[0]);
        return 1;
    }

    *(FARPROC *) &pIsWow64Process =
        GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process");

    if(wcscmp(argv[1], L"-p") == 0 || wcscmp(argv[1], L"--pid") == 0) {
        uint32_t pid = wcstoul(argv[2], NULL, 10);
        return determine_process_identifier(pid);
    }

    if(wcscmp(argv[1], L"-n") == 0 ||
            wcscmp(argv[1], L"--process-name") == 0) {
        uint32_t pid = pid_from_process_name(argv[2]);
        return determine_process_identifier(pid);
    }

    if(wcscmp(argv[1], L"-f") == 0 || wcscmp(argv[1], L"--file") == 0) {
        return determine_pe_file(argv[2]);
    }

    fprintf(stderr, "Invalid action specified..\n");
    return 1;
}
