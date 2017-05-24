/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2017 Cuckoo Foundation.

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

#include <windows.h>

LRESULT CALLBACK window_callback(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if(message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }

    // The button has been clicked (?).
    if(message == WM_COMMAND) {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, message, wparam, lparam);
}

int main()
{
    WNDCLASSEX wcex;

    memset(&wcex, 0, sizeof(wcex));
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = window_callback;
    wcex.lpszClassName = "uniwindow";
    RegisterClassEx(&wcex);

    HWND window_handle = CreateWindowExA(
        0, "uniwindow", NULL, 0, 0, 0, 200, 200, NULL, NULL, NULL, NULL
    );
    CreateWindowExW(
        0, L"BUTTON", L"unicode \u202e title OK",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        10, 10, 20, 20, window_handle, NULL, NULL, NULL
    );

    ShowWindow(window_handle, SW_SHOW);
    UpdateWindow(window_handle);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) != FALSE) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
