Signature::

    * Calling convention: WINAPI
    * Category: registry
    * Is success: ret == ERROR_SUCCESS
    * Library: advapi32
    * Return value: LONG


RegOpenKeyExA
=============

Parameters::

    ** HKEY hKey base_handle
    ** LPCTSTR lpSubKey regkey_r
    ** DWORD ulOptions options
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Interesting::

    u regkey
    i options
    i access

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegOpenKeyExW
=============

Parameters::

    ** HKEY hKey base_handle
    ** LPWSTR lpSubKey regkey_r
    ** DWORD ulOptions options
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Interesting::

    u regkey
    i options
    i access

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegCreateKeyExA
===============

Parameters::

    ** HKEY hKey base_handle
    ** LPCTSTR lpSubKey regkey_r
    *  DWORD Reserved
    ** LPTSTR lpClass class
    ** DWORD dwOptions options
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    ** LPDWORD lpdwDisposition disposition

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Interesting::

    u regkey
    s class
    i options
    i access
    I disposition

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegCreateKeyExW
===============

Parameters::

    ** HKEY hKey base_handle
    ** LPWSTR lpSubKey regkey_r
    *  DWORD Reserved
    ** LPWSTR lpClass class
    ** DWORD dwOptions options
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    ** LPDWORD lpdwDisposition disposition

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Interesting::

    u regkey
    u class
    i options
    i access
    I disposition

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegDeleteKeyA
=============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpSubKey regkey_r

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegDeleteKeyW
=============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpSubKey regkey_r

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegEnumKeyW
===========

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPWSTR lpName key_name
    *  DWORD cchName

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

Interesting::

    u regkey
    i index

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegEnumKeyExA
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPTSTR lpName key_name
    *  LPDWORD lpcName
    *  LPDWORD lpReserved
    ** LPTSTR lpClass class
    *  LPDWORD lpcClass
    *  PFILETIME lpftLastWriteTime

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

Interesting::

    u regkey
    i index

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegEnumKeyExW
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPWSTR lpName key_name
    *  LPDWORD lpcName
    *  LPDWORD lpReserved
    ** LPWSTR lpClass class
    *  LPDWORD lpcClass
    *  PFILETIME lpftLastWriteTime

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

Interesting::

    u regkey
    i index

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegEnumValueA
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPTSTR lpValueName regkey_r
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Flags::

    reg_type

Ensure::

    lpType
    lpcbData

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

    *lpType = REG_NONE;

Logging::

    u regkey regkey
    r value lpType, lpcbData, lpData

Post::

    free_unicode_buffer(regkey);


RegEnumValueW
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPWSTR lpValueName regkey_r
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Flags::

    reg_type

Ensure::

    lpType
    lpcbData

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

    *lpType = REG_NONE;

Logging::

    u regkey regkey
    R value lpType, lpcbData, lpData

Post::

    free_unicode_buffer(regkey);


RegSetValueExA
==============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName regkey_r
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Flags::

    reg_type

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Interesting::

    u regkey
    i reg_type
    b cbData, lpData

Logging::

    u regkey regkey
    r value &dwType, &cbData, lpData

Post::

    free_unicode_buffer(regkey);


RegSetValueExW
==============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName regkey_r
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Flags::

    reg_type

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

Interesting::

    u regkey
    i reg_type
    b cbData, lpData

Logging::

    u regkey regkey
    R value &dwType, &cbData, lpData

Post::

    free_unicode_buffer(regkey);


RegQueryValueExA
================

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName regkey_r
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Flags::

    reg_type

Ensure::

    lpType
    lpcbData

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

    *lpType = REG_NONE;

Interesting::

    u regkey

Logging::

    u regkey regkey
    r value lpType, lpcbData, lpData

Post::

    free_unicode_buffer(regkey);


RegQueryValueExW
================

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName regkey_r
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Flags::

    reg_type

Ensure::

    lpType
    lpcbData

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

    *lpType = REG_NONE;

Interesting::

    u regkey

Logging::

    u regkey regkey
    R value lpType, lpcbData, lpData

Post::

    free_unicode_buffer(regkey);


RegDeleteValueA
===============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName regkey_r

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegDeleteValueW
===============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName regkey_r

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegQueryInfoKeyA
================

Parameters::

    ** HKEY hKey key_handle
    ** LPTSTR lpClass class
    *  LPDWORD lpcClass
    *  LPDWORD lpReserved
    ** LPDWORD lpcSubKeys subkey_count
    ** LPDWORD lpcMaxSubKeyLen subkey_max_length
    ** LPDWORD lpcMaxClassLen class_max_length
    ** LPDWORD lpcValues value_count
    ** LPDWORD lpcMaxValueNameLen value_name_max_length
    ** LPDWORD lpcMaxValueLen value_max_length
    *  LPDWORD lpcbSecurityDescriptor
    *  PFILETIME lpftLastWriteTime

Ensure::

    lpcSubKeys
    lpcMaxSubKeyLen
    lpcMaxClassLen
    lpcValues
    lpcMaxValueNameLen
    lpcMaxValueLen

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegQueryInfoKeyW
================

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpClass class
    *  LPDWORD lpcClass
    *  LPDWORD lpReserved
    ** LPDWORD lpcSubKeys subkey_count
    ** LPDWORD lpcMaxSubKeyLen subkey_max_length
    ** LPDWORD lpcMaxClassLen class_max_length
    ** LPDWORD lpcValues value_count
    ** LPDWORD lpcMaxValueNameLen value_name_max_length
    ** LPDWORD lpcMaxValueLen value_max_length
    *  LPDWORD lpcbSecurityDescriptor
    *  PFILETIME lpftLastWriteTime

Ensure::

    lpcSubKeys
    lpcMaxSubKeyLen
    lpcMaxClassLen
    lpcValues
    lpcMaxValueNameLen
    lpcMaxValueLen

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


RegCloseKey
===========

Parameters::

    ** HKEY hKey key_handle
