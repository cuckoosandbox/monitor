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
#include "ntapi.h"

#define IGNORE_MATCH(s) \
    if(!wcsnicmp(fname, s, length)) return TRUE

#define IGNORE_START(s) \
    if(!wcsnicmp(fname, s, sizeof(s)/sizeof(wchar_t)-1)) return TRUE

BOOL is_ignored_file_unicode(const wchar_t *fname, int length)
{
    IGNORE_MATCH(L"\\??\\PIPE\\lsarpc");
    IGNORE_MATCH(L"\\??\\MountPointManager");
    IGNORE_START(L"\\??\\IDE#");
    IGNORE_START(L"\\??\\STORAGE#");
    IGNORE_START(L"\\??\\root#");
    // IGNORE_START(L"\\Device\\");
    return FALSE;
}
