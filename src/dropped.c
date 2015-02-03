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
#include <shlwapi.h>
#include "ignore.h"
#include "memory.h"
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"

static array_t g_handles;

void dropped_init()
{
    array_init(&g_handles);
}

void dropped_add(HANDLE file_handle, const wchar_t *filepath)
{
    uintptr_t index = (uintptr_t) file_handle / 4;

    if(is_ignored_filepath(filepath) == 0) {
        array_set(&g_handles, index, wcsdup(filepath));
    }
}

void dropped_wrote(HANDLE file_handle)
{
    uintptr_t index = (uintptr_t) file_handle / 4;

    wchar_t *filepath = (wchar_t *) array_get(&g_handles, index);
    if(filepath != NULL) {
        pipe("FILE_NEW:%Z", filepath);
        array_unset(&g_handles, index);
        mem_free(filepath);
    }
}

void dropped_close(HANDLE file_handle)
{
    uintptr_t index = (uintptr_t) file_handle / 4;

    // If set, the value will be the filepath, so let's deallocate it.
    mem_free(array_get(&g_handles, index));

    array_unset(&g_handles, index);
}
