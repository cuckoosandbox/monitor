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

    char value[10], value2[10], *name, *type;

    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

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

    wchar_t value[10], value2[10], *name, *type;

    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

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

    char value[10], value2[10], *name, *type;

    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

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

    wchar_t value[10], value2[10], *name, *type;

    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

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
