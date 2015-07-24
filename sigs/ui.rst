Signature::

    * Calling convention: WINAPI
    * Category: ui
    * Library: user32
    * Return value: HWND


FindWindowA
===========

Parameters::

    *  LPCTSTR lpClassName
    ** LPCTSTR lpWindowName window_name

Pre::

    char value[10]; const char *class_name = lpClassName;
    if(((uintptr_t) lpClassName & 0xffff) == (uintptr_t) lpClassName) {
        our_snprintf(value, sizeof(value),
            "#%d", (uint16_t) (uintptr_t) lpClassName);
        class_name = value;
    }

Interesting::

    s class_name
    s window_name

Logging::

    s class_name class_name


FindWindowW
===========

Parameters::

    *  LPWSTR lpClassName
    ** LPWSTR lpWindowName window_name

Pre::

    char temp[10]; wchar_t value[10]; const wchar_t *class_name = lpClassName;
    if(((uintptr_t) lpClassName & 0xffff) == (uintptr_t) lpClassName) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpClassName);
        wcsncpyA(value, temp, sizeof(temp));
        class_name = value;
    }

Interesting::

    u class_name
    u window_name

Logging::

    u class_name class_name


FindWindowExA
=============

Parameters::

    ** HWND hwndParent parent_hwnd
    ** HWND hwndChildAfter child_after_hwnd
    *  LPCTSTR lpszClass
    ** LPCTSTR lpszWindow window_name

Pre::

    char value[10]; const char *class_name = lpszClass;
    if(((uintptr_t) lpszClass & 0xffff) == (uintptr_t) lpszClass) {
        our_snprintf(value, sizeof(value),
            "#%d", (uint16_t) (uintptr_t) lpszClass);
        class_name = value;
    }

Interesting::

    s class_name
    s window_name

Logging::

    s class_name class_name


FindWindowExW
=============

Parameters::

    ** HWND hwndParent parent_hwnd
    ** HWND hwndChildAfter child_after_hwnd
    *  LPWSTR lpszClass
    ** LPWSTR lpszWindow window_name

Pre::

    char temp[10]; wchar_t value[10]; const wchar_t *class_name = lpszClass;
    if(((uintptr_t) lpszClass & 0xffff) == (uintptr_t) lpszClass) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpszClass);
        wcsncpyA(value, temp, sizeof(temp));
        class_name = value;
    }

Interesting::

    u class_name
    u window_name

Logging::

    s class_name class_name


MessageBoxTimeoutA
==================

Parameters::

    ** HWND hWnd window_handle
    ** LPCTSTR lpText text
    ** LPCTSTR lpCaption caption
    ** UINT uType flags
    ** WORD wLanguageId language_identifier
    *  INT Unknown

Interesting::

    s text
    s caption
    i flags
    i language_identifier


MessageBoxTimeoutW
==================

Parameters::

    ** HWND hWnd window_handle
    ** LPWSTR lpText text
    ** LPWSTR lpCaption caption
    ** UINT uType flags
    ** WORD wLanguageId language_identifier
    *  INT Unknown

Interesting::

    u text
    u caption
    i flags
    i language_identifier


DrawTextExA
===========

Parameters::

    *  HDC hdc
    *  LPSTR lpchText
    *  int cchText
    *  LPRECT lprc
    *  UINT dwDTFormat
    *  LPDRAWTEXTPARAMS lpDTParams

Middle::

    if(cchText == -1) {
        cchText = strlen(lpchText);
    }

Logging::

    S string cchText, lpchText


DrawTextExW
===========

Parameters::

    *  HDC hdc
    *  LPWSTR lpchText
    *  int cchText
    *  LPRECT lprc
    *  UINT dwDTFormat
    *  LPDRAWTEXTPARAMS lpDTParams

Middle::

    if(cchText == -1) {
        cchText = lstrlenW(lpchText);
    }

Logging::

    U string cchText, lpchText


LoadStringA
===========

Parameters::

    ** HINSTANCE hInstance module_handle
    ** UINT uID id
    *  LPSTR lpBuffer
    *  int nBufferMax

Middle::

    const char *buf = lpBuffer;
    if(nBufferMax == 0 && lpBuffer != NULL) {
        buf = *(const char **) lpBuffer;
    }

Logging::

    s string buf


LoadStringW
===========

Parameters::

    ** HINSTANCE hInstance module_handle
    ** UINT uID id
    *  LPWSTR lpBuffer
    *  int nBufferMax

Middle::

    const wchar_t *buf = lpBuffer;
    if(nBufferMax == 0 && lpBuffer != NULL) {
        buf = *(const wchar_t **) lpBuffer;
    }

Logging::

    u string buf


_CreateWindowExA
================

Parameters::

    ** DWORD dwExStyle extended_style
    ** LPCTSTR lpClassName class_name
    ** LPCTSTR lpWindowName window_name
    ** DWORD dwStyle style
    ** int x
    ** int y
    ** int nWidth width
    ** int nHeight height
    ** HWND hWndParent parent_handle
    ** HMENU hMenu menu_handle
    ** HINSTANCE hInstance instance_handle
    *  LPVOID lpParam

Flags::

    extended_style
    style


_CreateWindowExW
================

Parameters::

    ** DWORD dwExStyle extended_style
    ** LPWSTR lpClassName class_name
    ** LPWSTR lpWindowName window_name
    ** DWORD dwStyle style
    ** int x
    ** int y
    ** int nWidth width
    ** int nHeight height
    ** HWND hWndParent parent_handle
    ** HMENU hMenu menu_handle
    ** HINSTANCE hInstance instance_handle
    *  LPVOID lpParam

Flags::

    extended_style
    style
