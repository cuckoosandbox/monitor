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
    *  LPCTSTR lpSubKey
    *  DWORD ulOptions options
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegOpenKeyExW
=============

Parameters::

    ** HKEY hKey base_handle
    *  LPWSTR lpSubKey
    *  DWORD ulOptions
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegCreateKeyExA
===============

Parameters::

    ** HKEY hKey base_handle
    *  LPCTSTR lpSubKey
    *  DWORD Reserved
    ** LPTSTR lpClass class
    *  DWORD dwOptions
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    *  LPDWORD lpdwDisposition

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegCreateKeyExW
===============

Parameters::

    ** HKEY hKey base_handle
    *  LPWSTR lpSubKey
    *  DWORD Reserved
    ** LPWSTR lpClass class
    *  DWORD dwOptions
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    *  LPDWORD lpdwDisposition

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegDeleteKeyA
=============

Parameters::

    ** HKEY hKey key_handle
    *  LPCTSTR lpSubKey

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegDeleteKeyW
=============

Parameters::

    ** HKEY hKey key_handle
    *  LPWSTR lpSubKey

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpSubKey, regkey);

Logging::

    u regkey regkey


RegEnumKeyW
===========

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPWSTR lpName key_name
    *  DWORD cchName

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key(hKey, regkey);

Logging::

    u regkey regkey


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

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key(hKey, regkey);

Logging::

    u regkey regkey


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

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key(hKey, regkey);

Logging::

    u regkey regkey


RegEnumValueA
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    *  LPTSTR lpValueName
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    B buffer lpcbData, lpData


RegEnumValueW
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    *  LPWSTR lpValueName
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    B buffer lpcbData, lpData


RegSetValueExA
==============

Parameters::

    ** HKEY hKey key_handle
    *  LPCTSTR lpValueName
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    b buffer cbData, lpData


RegSetValueExW
==============

Parameters::

    ** HKEY hKey key_handle
    *  LPWSTR lpValueName
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    b buffer cbData, lpData


RegQueryValueExA
================

Parameters::

    ** HKEY hKey key_handle
    *  LPCTSTR lpValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    B buffer lpcbData, lpData


RegQueryValueExW
================

Parameters::

    ** HKEY hKey key_handle
    *  LPWSTR lpValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey
    B buffer lpcbData, lpData


RegDeleteValueA
===============

Parameters::

    ** HKEY hKey key_handle
    *  LPCTSTR lpValueName

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_asciiz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey


RegDeleteValueW
===============

Parameters::

    ** HKEY hKey key_handle
    *  LPWSTR lpValueName

Pre::

    wchar_t regkey[MAX_PATH_W+1];
    reg_get_key_uniz(hKey, lpValueName, regkey);

Logging::

    u regkey regkey


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


RegCloseKey
===========

Parameters::

    ** HKEY hKey key_handle
