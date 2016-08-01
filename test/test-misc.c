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
#include <stdint.h>
#include <winsock2.h>
#include "config.h"
#include "hooking.h"
#include "misc.h"
#include "native.h"
#include "pipe.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }
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

NTSTATUS (WINAPI *pZwDeleteFile)(POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS (WINAPI *pZwCreateFile)(PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID AllocationSize,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

NTSTATUS (WINAPI *pZwSetInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

void test_path_native()
{
    UNICODE_STRING dir_fname, file_fname;
    OBJECT_ATTRIBUTES obj_dir, obj_file;
    IO_STATUS_BLOCK io_dir;
    HANDLE dir_handle;

    *(FARPROC *) &pRtlInitUnicodeString = GetProcAddress(
        GetModuleHandle("ntdll"), "RtlInitUnicodeString");
    *(FARPROC *) &pZwDeleteFile = GetProcAddress(
        GetModuleHandle("ntdll"), "ZwDeleteFile");
    *(FARPROC *) &pZwCreateFile = GetProcAddress(
        GetModuleHandle("ntdll"), "ZwCreateFile");
    *(FARPROC *) &pZwSetInformationFile = GetProcAddress(
        GetModuleHandle("ntdll"), "ZwSetInformationFile");

    wchar_t *path = get_unicode_buffer();

    CreateDirectory("C:\\cuckoomonitor-native", NULL);
    SetCurrentDirectory("C:\\cuckoomonitor-native");

    pRtlInitUnicodeString(&dir_fname, L"\\??\\C:\\cuckoomonitor");
    pRtlInitUnicodeString(&file_fname, L"abc.txt");

    assert(path_get_full_path_unistr(&dir_fname, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor") == 0);

    InitializeObjectAttributes(&obj_dir, &dir_fname,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    memset(path, 0, MAX_PATH_W * sizeof(wchar_t));
    assert(path_get_full_path_objattr(&obj_dir, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor") == 0);

    NTSTATUS ret = pZwCreateFile(&dir_handle, FILE_TRAVERSE, &obj_dir,
        &io_dir, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_DIRECTORY_FILE, NULL, 0);
    assert(NT_SUCCESS(ret));

    memset(path, 0, MAX_PATH_W * sizeof(wchar_t));
    assert(path_get_full_path_handle(dir_handle, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor") == 0);

    InitializeObjectAttributes(&obj_file, &file_fname,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, dir_handle, NULL);

    assert(path_get_full_path_objattr(&obj_file, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor\\abc.txt") == 0);

    free_unicode_buffer(path);
}

int main()
{
    static char buf[0x1000]; static wchar_t bufW[0x1000];

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    hook_init(GetModuleHandle(NULL));
    assert(native_init() == 0);
    misc_init("hoi");

    assert(ultostr(42, buf, 10) == 2 && strcmp(buf, "42") == 0);
    assert(ultostr(1337, buf, 10) == 4 && strcmp(buf, "1337") == 0);
    assert(ultostr(-20, buf, 10) == 3 && strcmp(buf, "-20") == 0);
    assert(ultostr(-42, buf, 10) == 3 && strcmp(buf, "-42") == 0);
    assert(ultostr(0x1337, buf, 16) == 4 && strcmp(buf, "1337") == 0);

    assert(ultostr(0xffffffff, buf, 16) == 8 && strcmp(buf, "ffffffff") == 0);
    assert(ultostr(0xffffffffffffffff, buf, 16) == 16 && strcmp(buf, "ffffffffffffffff") == 0);

    assert(our_snprintf(buf, 3, "hoi") == 2 && strcmp(buf, "ho") == 0);
    assert(our_snprintf(buf, 4, "hoi") == 3 && strcmp(buf, "hoi") == 0);
    assert(our_snprintf(buf, 4, "hello") == 3 && strcmp(buf, "hel") == 0);
    assert(our_snprintf(buf, 64, "%s %s", "a", "b") == 3 && memcmp(buf, "a b", 3) == 0);
    assert(our_snprintf(buf, 64, "%s %s ccc", "a", "bb") == 8 && memcmp(buf, "a bb ccc", 8) == 0);
    assert(our_snprintf(buf, 64, "%p", 0x4141) == 6 && memcmp(buf, "0x4141", 6) == 0);
    assert(our_snprintf(buf, 64, "%p %p", 0x4141, 0x4242) == 13 && memcmp(buf, "0x4141 0x4242", 13) == 0);
    assert(our_snprintf(buf, 64, "%d %d", 9001, -42) == 8 && strcmp(buf, "9001 -42") == 0);
    assert(our_snprintf(buf, 64, "%p", 0xffffffff) == 10 && strcmp(buf, "0xffffffff") == 0);

    assert((wcsncpyA(bufW, "hello", 4), wcscmp(bufW, L"hel") == 0));
    assert((wcsncpyA(bufW, "hello", 5), wcscmp(bufW, L"hell") == 0));
    assert((wcsncpyA(bufW, "hello", 6), wcscmp(bufW, L"hello") == 0));
    assert((wcsncpyA(bufW, "hello", 64), wcscmp(bufW, L"hello") == 0));

    UNICODE_STRING unistr = {
        .Length = 10, .MaximumLength = 10, .Buffer = L"HELLO",
    };
    OBJECT_ATTRIBUTES objattr = {
        .ObjectName = &unistr,
    };

    assert(wcscmp(extract_unicode_string_unistr(&unistr), L"HELLO") == 0);
    assert(wcscmp(extract_unicode_string_objattr(&objattr), L"HELLO") == 0);

    struct sockaddr_in addr; const char *ip; int port;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(80);
    assert((get_ip_port((struct sockaddr *) &addr, &ip, &port), strcmp(ip, "127.0.0.1") == 0 && port == 80));

    assert(our_htons(1337) == htons(1337));
    assert(our_htons(0x4141) == htons(0x4141));
    assert(our_htonl(0x11223344) == htonl(0x11223344));
    assert(our_htonl(0x22446688) == 0x88664422);

    assert(strcmp(our_inet_ntoa(addr.sin_addr), "127.0.0.1") == 0);
    addr.sin_addr.s_addr = inet_addr("1.2.3.4");
    assert(strcmp(inet_ntoa(addr.sin_addr), our_inet_ntoa(addr.sin_addr)) == 0);

    wchar_t *path = get_unicode_buffer();

    assert(path_get_full_pathA("C:\\Windows\\System32\\kernel32.dll", path) != 0);
    assert(wcsicmp(path, L"C:\\Windows\\System32\\kernel32.dll") == 0);

    assert(QueryDosDeviceA("C:", buf, MAX_PATH) != 0);
    strcat(buf, "\\Windows\\System32\\explorer.exe");
    assert(path_get_full_pathA(buf, path) != 0);
    assert(wcsicmp(path, L"C:\\Windows\\System32\\explorer.exe") == 0);

    assert(path_get_full_pathA("\\Systemroot\\System32\\advapi32.dll", path) != 0);
    assert(wcsicmp(path, L"C:\\Windows\\System32\\advapi32.dll") == 0);

    assert(path_get_full_pathA("C:\\Windows\\404", path) != 0);
    assert(wcsicmp(path, L"C:\\Windows\\404") == 0);

    assert(path_get_full_pathA("C:\\Windows\\404\\404", path) != 0);
    assert(wcsicmp(path, L"C:\\Windows\\404\\404") == 0);

    assert(path_get_full_pathA("C:\\PROGRA~1\\INTERN~1\\iexplore.exe", path) != 0);
    assert(wcsicmp(path, L"C:\\Program Files\\Internet Explorer\\iexplore.exe") == 0);

    CreateDirectory("C:\\cuckoomonitor", NULL);
    SetCurrentDirectory("C:\\cuckoomonitor");
    assert(path_get_full_path_unistr(&unistr, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor\\HELLO") == 0);

    unistr.Buffer = L"HEY"; unistr.Length = unistr.MaximumLength = 6;
    assert(path_get_full_path_objattr(&objattr, path) != 0);
    assert(wcsicmp(path, L"C:\\cuckoomonitor\\HEY") == 0);

    test_path_native();
    return 0;
}
