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
#include <windows.h>
#include "memory.h"
#include "ntapi.h"
#include "pipe.h"

#define IGNORE_MATCH(s) \
    if(wcsicmp(fname, s) == 0) return 1

#define IGNORE_START(s) \
    if(wcsnicmp(fname, s, sizeof(s)/sizeof(wchar_t)-1) == 0) return 1

static array_t g_ignored_handles;

void ignore_init()
{
    array_init(&g_ignored_handles);
}

int is_ignored_filepath(const wchar_t *fname)
{
    IGNORE_MATCH(L"\\\\?\\MountPointManager");

    IGNORE_START(L"\\\\?\\PIPE\\");
    IGNORE_START(L"\\\\?\\IDE#");
    IGNORE_START(L"\\\\?\\STORAGE#");
    IGNORE_START(L"\\\\?\\root#");
    IGNORE_START(L"\\BaseNamedObjects\\");
    IGNORE_START(L"\\Callback\\");
    IGNORE_START(L"\\Device\\");
    IGNORE_START(L"\\Drivers\\");
    IGNORE_START(L"\\FileSystem\\");
    IGNORE_START(L"\\KnownDlls\\");
    IGNORE_START(L"\\Nls\\");
    IGNORE_START(L"\\ObjectTypes\\");
    IGNORE_START(L"\\RPC Controls\\");
    IGNORE_START(L"\\Security\\");
    IGNORE_START(L"\\Window\\");
    IGNORE_START(L"\\Sessions\\");
    return 0;
}

static const wchar_t *g_ignored_processpaths[] = {
    L"C:\\WINDOWS\\system32\\dwwin.exe",
    L"C:\\WINDOWS\\system32\\dumprep.exe",
    L"C:\\WINDOWS\\system32\\drwtsn32.exe",
    NULL,
};

int is_ignored_process()
{
    wchar_t process_path[MAX_PATH];
    GetModuleFileNameW(NULL, process_path, MAX_PATH);
    GetLongPathNameW(process_path, process_path, MAX_PATH);

    for (uint32_t idx = 0; g_ignored_processpaths[idx] != NULL; idx++) {
        if(!wcsicmp(g_ignored_processpaths[idx], process_path)) {
            return 1;
        }
    }
    return 0;
}

void ignored_object_add(HANDLE object_handle)
{
    uintptr_t index = (uintptr_t) object_handle / 4;

    // The value doesn't matter - it just has to be non-null.
    if(array_set(&g_ignored_handles, index, &ignored_object_add) < 0) {
        pipe("CRITICAL:Error adding ignored object handle!");
    }
}

void ignored_object_remove(HANDLE object_handle)
{
    uintptr_t index = (uintptr_t) object_handle / 4;

    array_unset(&g_ignored_handles, index);
}

int is_ignored_object_handle(HANDLE object_handle)
{
    uintptr_t index = (uintptr_t) object_handle / 4;

    return array_get(&g_ignored_handles, index) != NULL;
}
