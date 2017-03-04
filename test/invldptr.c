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

// This program throws an invalid pointer at a function that the Cuckoo
// Monitor is hooking.

/// OBJECTS=

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "ntapi.h"

#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_KERNEL_HANDLE 0x00000200

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
    }

VOID (WINAPI *pRtlInitUnicodeString)(PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

NTSTATUS (WINAPI *pNtCreateFile)(PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID AllocationSize,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

NTSTATUS (WINAPI *pNtOpenProcess)(PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

int main()
{
    *(FARPROC *) &pRtlInitUnicodeString =
        GetProcAddress(GetModuleHandle("ntdll"), "RtlInitUnicodeString");
    *(FARPROC *) &pNtCreateFile =
        GetProcAddress(GetModuleHandle("ntdll"), "NtCreateFile");
    *(FARPROC *) &pNtOpenProcess =
        GetProcAddress(GetModuleHandle("ntdll"), "NtOpenProcess");

    wchar_t path[MAX_PATH] = L"\\??\\";
    GetCurrentDirectoryW(MAX_PATH-4, path+4);
    wcscat(path, L"\\a.txt");

    UNICODE_STRING file_fname;
    pRtlInitUnicodeString(&file_fname, path);

    OBJECT_ATTRIBUTES obj_file;
    InitializeObjectAttributes(&obj_file, &file_fname,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE file_handle; IO_STATUS_BLOCK io_file;
    NTSTATUS ret = pNtCreateFile(&file_handle, GENERIC_WRITE, &obj_file,
        &io_file, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
        FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);

    printf("ret-normal: 0x%lx\n", ret);

    file_fname.Buffer = (wchar_t *) 0x11223344;
    ret = pNtCreateFile(&file_handle, GENERIC_WRITE, &obj_file,
        &io_file, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
        FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);

    printf("ret-invld1: 0x%lx\n", ret);

    obj_file.ObjectName = (UNICODE_STRING *) 0x55667788;
    ret = pNtCreateFile(&file_handle, GENERIC_WRITE, &obj_file,
        &io_file, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
        FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);

    printf("ret-invld2: 0x%lx\n", ret);

    ret = pNtOpenProcess(NULL, 0, NULL, (PCLIENT_ID) 0x11223344);
    printf("ret-invld3: 0x%lx\n", ret);
    return 0;
}
