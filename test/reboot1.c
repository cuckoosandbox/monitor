/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2016 Cuckoo Foundation.

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
#include <winsock2.h>
#include <windows.h>

void install()
{
    wchar_t filepath[MAX_PATH]; uint32_t length;
    length = GetModuleFileNameW(NULL, &filepath[1], MAX_PATH);

    filepath[0] = '"';
    wcscpy(&filepath[1+length], L"\" evil");

    HKEY key_handle;
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
            KEY_ALL_ACCESS, NULL, &key_handle, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(key_handle, L"reboot1", 0, REG_SZ,
            (void *) filepath, (lstrlenW(filepath) + 1) * sizeof(wchar_t));
        RegCloseKey(key_handle);
    }
}

int main(int argc, char *argv[])
{
    if(argc == 1) {
        install();
        return 0;
    }

    WSADATA wsadata;
    WSAStartup(0x202, &wsadata);

    char hostname[128];
    snprintf(hostname, sizeof(hostname), "%s.cuckoo.sh", argv[1]);
    gethostbyname(hostname);
}
