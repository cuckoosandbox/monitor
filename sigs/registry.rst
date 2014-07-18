Signature::

    * Calling convention: WINAPI
    * Category: registry
    * Is success: ret == ERROR_SUCCESS
    * Library: advapi32
    * Return value: LONG


RegOpenKeyExA
=============

Parameters::

    ** HKEY hKey base_key_handle
    ** LPCTSTR lpSubKey sub_key
    *  DWORD ulOptions options
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle


RegOpenKeyExW
=============

Parameters::

    ** HKEY hKey base_key_handle
    ** LPWSTR lpSubKey sub_key
    *  DWORD ulOptions
    ** REGSAM samDesired access
    ** PHKEY phkResult key_handle


RegCreateKeyExA
===============

Parameters::

    ** HKEY hKey base_key_handle
    ** LPCTSTR lpSubKey sub_key
    *  DWORD Reserved
    ** LPTSTR lpClass class
    *  DWORD dwOptions
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    *  LPDWORD lpdwDisposition


RegCreateKeyExW
===============

Parameters::

    ** HKEY hKey base_key_handle
    ** LPWSTR lpSubKey sub_key
    *  DWORD Reserved
    ** LPWSTR lpClass class
    *  DWORD dwOptions
    ** REGSAM samDesired access
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult key_handle
    *  LPDWORD lpdwDisposition


RegDeleteKeyA
=============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpSubKey sub_key


RegDeleteKeyW
=============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpSubKey sub_key


RegEnumKeyW
===========

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    *  LPWSTR lpName
    *  DWORD cchName

Logging::

    u key_name lpName


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


RegEnumValueA
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPTSTR lpValueName value_name
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Logging::

    B buffer lpcbData, lpData


RegEnumValueW
=============

Parameters::

    ** HKEY hKey key_handle
    ** DWORD dwIndex index
    ** LPWSTR lpValueName value_name
    *  LPDWORD lpcchValueName
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Logging::

    B buffer lpcbData, lpData


RegSetValueExA
==============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName value_name
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Logging::

    b buffer cbData, lpData


RegSetValueExW
==============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName value_name
    *  DWORD Reserved
    ** DWORD dwType reg_type
    *  const BYTE *lpData
    *  DWORD cbData

Logging::

    b buffer cbData, lpData


RegQueryValueExA
================

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName value_name
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Logging::

    B buffer lpcbData, lpData


RegQueryValueExW
================

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName value_name
    *  LPDWORD lpReserved
    ** LPDWORD lpType reg_type
    *  LPBYTE lpData
    *  LPDWORD lpcbData

Ensure::

    lpcbData

Logging::

    B buffer lpcbData, lpData


RegDeleteValueA
===============

Parameters::

    ** HKEY hKey key_handle
    ** LPCTSTR lpValueName value_name


RegDeleteValueW
===============

Parameters::

    ** HKEY hKey key_handle
    ** LPWSTR lpValueName value_name


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
