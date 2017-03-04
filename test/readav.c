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

// This program demonstrates the logging of invalid and incomplete pointers.

/// OBJECTS=

#include <stdio.h>
#include <windows.h>

int main()
{
    char *ptr = VirtualAlloc(
        NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
    );

    memcpy(ptr+0x1000-11, "hello world", 11);

    HANDLE file_handle = CreateFile("readav.txt", GENERIC_WRITE,
        FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD bytes_written;
    WriteFile(file_handle, ptr+0x1000-11, 11, &bytes_written, NULL);
    WriteFile(file_handle, ptr+0x1000-11, 12, &bytes_written, NULL);
    WriteFile(file_handle, (const void *) 1, 20, &bytes_written, NULL);
}
