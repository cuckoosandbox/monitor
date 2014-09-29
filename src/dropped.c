/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2014 Cuckoo Foundation.

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
#include <shlwapi.h>
#include "hashtable.h"
#include "ignore.h"
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"

#define HDDVOL1 L"\\Device\\HarddiskVolume1"

static ht_t g_files;
static CRITICAL_SECTION g_mutex;

typedef struct _dropped_entry_t {
    uint32_t written;
    uint32_t length;
    wchar_t path[MAX_PATH_W+1];
} dropped_entry_t;

void dropped_init()
{
    ht_init(&g_files, sizeof(dropped_entry_t *));
    InitializeCriticalSection(&g_mutex);
}

void dropped_add(HANDLE file_handle, const wchar_t *filepath)
{
    dropped_entry_t *e;

    if(PathIsDirectoryW(filepath) == FALSE &&
            is_ignored_file_unicode(filepath, lstrlenW(filepath)) == 0) {

        e = (dropped_entry_t *) calloc(1, sizeof(dropped_entry_t));
        if(e != NULL) {
            wcscpy(e->path, filepath);

            EnterCriticalSection(&g_mutex);
            ht_insert(&g_files, (uintptr_t) file_handle, e);
            LeaveCriticalSection(&g_mutex);
        }
    }
}

void dropped_wrote(HANDLE file_handle)
{
    EnterCriticalSection(&g_mutex);

    dropped_entry_t **e = (dropped_entry_t **)
        ht_lookup(&g_files, (uintptr_t) file_handle, NULL);
    if(e != NULL && *e != NULL) {
        pipe("FILE_NEW:%Z", (*e)->path);
        ht_remove(&g_files, (uintptr_t) file_handle);
    }

    LeaveCriticalSection(&g_mutex);
}

void dropped_close(HANDLE file_handle)
{
    EnterCriticalSection(&g_mutex);

    ht_remove(&g_files, (uintptr_t) file_handle);

    LeaveCriticalSection(&g_mutex);
}
