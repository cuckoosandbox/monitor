Signature::

    * Calling convention: WINAPI
    * Category: ui
    * Return value: HWND


FindWindowA
===========

Parameters::

    *  LPCTSTR lpClassName
    ** LPCTSTR lpWindowName window_name

Pre::

    char value[10]; const char *class_name = lpClassName;
    if(((uintptr_t) lpClassName & 0xffff) == (uintptr_t) lpClassName) {
        sprintf(value, "#%d", (uintptr_t) lpClassName);
        class_name = value;
    }

Logging::

    s class_name class_name


FindWindowW
===========

Parameters::

    *  LPWSTR lpClassName
    ** LPWSTR lpWindowName window_name

Pre::

    wchar_t value[10]; const wchar_t *class_name = lpClassName;
    if(((uintptr_t) lpClassName & 0xffff) == (uintptr_t) lpClassName) {
        wsprintfW(value, L"#%d", (uintptr_t) lpClassName);
        class_name = value;
    }

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
        sprintf(value, "#%d", (uintptr_t) lpszClass);
        class_name = value;
    }

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

    wchar_t value[10]; const wchar_t *class_name = lpszClass;
    if(((uintptr_t) lpszClass & 0xffff) == (uintptr_t) lpszClass) {
        wsprintfW(value, L"#%d", (uintptr_t) lpszClass);
        class_name = value;
    }

Logging::

    s class_name class_name
