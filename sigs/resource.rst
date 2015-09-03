Signature::

    * Calling convention: WINAPI
    * Category: resource
    * Library: kernel32


FindResourceA
=============

Signature::

    * Return value: HRSRC

Parameters::

    ** HMODULE hModule module_handle
    *  LPCSTR lpName
    *  LPCSTR lpType

Pre::

    char value[10], value2[10];
    const char *name = lpName, *type = lpType;

    if(((uintptr_t) lpName & 0xffff) == (uintptr_t) lpName) {
        our_snprintf(value, sizeof(value),
            "#%d", (uint16_t) (uintptr_t) lpName);
        name = value;
    }

    if(((uintptr_t) lpType & 0xffff) == (uintptr_t) lpType) {
        our_snprintf(value2, sizeof(value2),
            "#%d", (uint16_t) (uintptr_t) lpType);
        type = value2;
    }

Logging::

    s name name
    s type type


FindResourceW
=============

Signature::

    * Return value: HRSRC

Parameters::

    ** HMODULE hModule module_handle
    *  LPWSTR lpName
    *  LPWSTR lpType

Pre::

    char temp[10]; wchar_t value[10], value2[10];
    const wchar_t *name = lpName, *type = lpType;

    if(((uintptr_t) lpName & 0xffff) == (uintptr_t) lpName) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpName);
        wcsncpyA(value, temp, sizeof(temp));
        name = value;
    }

    if(((uintptr_t) lpType & 0xffff) == (uintptr_t) lpType) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpType);
        wcsncpyA(value2, temp, sizeof(temp));
        type = value2;
    }

Logging::

    u name name
    u type type


FindResourceExA
===============

Signature::

    * Return value: HRSRC

Parameters::

    ** HMODULE hModule module_handle
    *  LPCSTR lpName
    *  LPCSTR lpType
    ** WORD wLanguage language_identifier

Pre::

    char value[10], value2[10];
    const char *name = lpName, *type = lpType;

    if(((uintptr_t) lpName & 0xffff) == (uintptr_t) lpName) {
        our_snprintf(value, sizeof(value),
            "#%d", (uint16_t) (uintptr_t) lpName);
        name = value;
    }

    if(((uintptr_t) lpType & 0xffff) == (uintptr_t) lpType) {
        our_snprintf(value2, sizeof(value2),
            "#%d", (uint16_t) (uintptr_t) lpType);
        type = value2;
    }

Logging::

    s name name
    s type type


FindResourceExW
===============

Signature::

    * Return value: HRSRC

Parameters::

    ** HMODULE hModule module_handle
    *  LPWSTR lpName
    *  LPWSTR lpType
    ** WORD wLanguage language_identifier

Pre::

    char temp[10]; wchar_t value[10], value2[10];
    const wchar_t *name = lpName, *type = lpType;

    if(((uintptr_t) lpName & 0xffff) == (uintptr_t) lpName) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpName);
        wcsncpyA(value, temp, sizeof(temp));
        name = value;
    }

    if(((uintptr_t) lpType & 0xffff) == (uintptr_t) lpType) {
        our_snprintf(temp, sizeof(temp),
            "#%d", (uint16_t) (uintptr_t) lpType);
        wcsncpyA(value2, temp, sizeof(temp));
        type = value2;
    }

Logging::

    u name name
    u type type


LoadResource
============

Signature::

    * Return value: HGLOBAL

Parameters::

    ** HMODULE hModule module_handle
    ** HRSRC hResInfo resource_handle

Logging::

    p pointer ret


SizeofResource
==============

Signature::

    * Is success: 1
    * Return value: DWORD

Parameters::

    ** HMODULE hModule module_handle
    ** HRSRC hResInfo resource_handle

Logging::

    i resource_size ret
