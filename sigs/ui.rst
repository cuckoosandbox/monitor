Signature::

    * Calling convention: WINAPI
    * Category: ui
    * Library: user32


FindWindowA
===========

Signature::

    * Return value: HWND

Parameters::

    *  LPCSTR lpClassName
    ** LPCTSTR lpWindowName window_name

Pre::

    char value[10], *class_name;

    int_or_strA(&class_name, lpClassName, value);

Interesting::

    s class_name
    s window_name

Logging::

    s class_name class_name


FindWindowW
===========

Signature::

    * Return value: HWND

Parameters::

    *  LPWSTR lpClassName
    ** LPWSTR lpWindowName window_name

Pre::

    wchar_t value[10], *class_name;

    int_or_strW(&class_name, lpClassName, value);

Interesting::

    u class_name
    u window_name

Logging::

    u class_name class_name


FindWindowExA
=============

Signature::

    * Return value: HWND

Parameters::

    ** HWND hwndParent parent_hwnd
    ** HWND hwndChildAfter child_after_hwnd
    *  LPCTSTR lpszClass
    ** LPCTSTR lpszWindow window_name

Pre::

    char value[10], *class_name;

    int_or_strA(&class_name, lpszClass, value);

Interesting::

    s class_name
    s window_name

Logging::

    s class_name class_name


FindWindowExW
=============

Signature::

    * Return value: HWND

Parameters::

    ** HWND hwndParent parent_hwnd
    ** HWND hwndChildAfter child_after_hwnd
    *  LPWSTR lpszClass
    ** LPWSTR lpszWindow window_name

Pre::

    wchar_t value[10], *class_name;

    int_or_strW(&class_name, lpszClass, value);

Interesting::

    u class_name
    u window_name

Logging::

    u class_name class_name


GetForegroundWindow
===================

Signature::

    * Return value: HWND


MessageBoxTimeoutA
==================

Signature::

    * Is success: ret != 0
    * Return value: int

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

Signature::

    * Is success: ret != 0
    * Return value: int

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

Signature::

    * Is success: ret != 0
    * Return value: int

Parameters::

    *  HDC hdc
    *  LPSTR lpchText
    *  int cchText
    *  LPRECT lprc
    *  UINT dwDTFormat
    *  LPDRAWTEXTPARAMS lpDTParams

Middle::

    if(cchText == -1) {
        cchText = copy_strlen(lpchText);
    }

Logging::

    S string cchText, lpchText


DrawTextExW
===========

Signature::

    * Is success: ret != 0
    * Return value: int

Parameters::

    *  HDC hdc
    *  LPWSTR lpchText
    *  int cchText
    *  LPRECT lprc
    *  UINT dwDTFormat
    *  LPDRAWTEXTPARAMS lpDTParams

Middle::

    if(cchText == -1) {
        cchText = copy_strlenW(lpchText);
    }

Logging::

    U string cchText, lpchText


LoadStringA
===========

Signature::

    * Is success: ret != 0
    * Return value: int

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

Signature::

    * Is success: ret != 0
    * Return value: int

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

Signature::

    * Return value: HWND

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

Signature::

    * Return value: HWND

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


_DialogBoxIndirectParamA
========================

Parameters::

    *  HINSTANCE hInstance
    *  LPCDLGTEMPLATE hDialogTemplate
    *  HWND hWndParent
    *  DLGPROC lpDialogFunc
    *  LPARAM dwInitParam


_DialogBoxIndirectParamW
========================

Parameters::

    *  HINSTANCE hInstance
    *  LPCDLGTEMPLATE hDialogTemplate
    *  HWND hWndParent
    *  DLGPROC lpDialogFunc
    *  LPARAM dwInitParam
