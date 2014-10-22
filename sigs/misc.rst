Signature::

    * Calling convention: WINAPI
    * Category: misc


GetSystemMetrics
================

Signature::

    * Is success: ret != 0
    * Library: user32
    * Return value: int

Parameters::

    ** int nIndex index


GetCursorPos
============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    *  LPPOINT lpPoint

Logging::

    l x lpPoint != NULL ? lpPoint->x : 0
    l y lpPoint != NULL ? lpPoint->y : 0


GetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    *  LPCSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    S computer_name *lpnSize, lpBuffer


GetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    *  LPWSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    U computer_name *lpnSize / sizeof(wchar_t), lpBuffer


GetUserNameA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    *  LPCSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    S user_name *lpnSize, lpBuffer


GetUserNameW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    *  LPWSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    U user_name *lpnSize / sizeof(wchar_t), lpBuffer


GetUserNameExA
==============

Signature::

    * Library: secur32
    * Return value: BOOL

Parameters::

    ** EXTENDED_NAME_FORMAT NameFormat name_format
    *  LPCSTR lpNameBuffer
    *  PULONG lpnSize

Ensure::

    lpnSize

Logging::

    S name *lpnSize, lpNameBuffer


GetUserNameExW
==============

Signature::

    * Library: secur32
    * Return value: BOOL

Parameters::

    ** EXTENDED_NAME_FORMAT NameFormat name_format
    *  LPWSTR lpNameBuffer
    *  PULONG lpnSize

Ensure::

    lpnSize

Logging::

    U name *lpnSize, lpNameBuffer


EnumWindows
===========

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    *  WNDENUMPROC lpEnumProc
    *  LPARAM lParam


GetDiskFreeSpaceW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpRootPathName root_path
    ** LPDWORD lpSectorsPerCluster sectors_per_cluster
    ** LPDWORD lpBytesPerSector bytes_per_sector
    ** LPDWORD lpNumberOfFreeClusters number_of_free_clusters
    ** LPDWORD lpTotalNumberOfClusters total_number_of_clusters


GetDiskFreeSpaceExW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpDirectoryName root_path
    ** PULARGE_INTEGER lpFreeBytesAvailable free_bytes_available
    ** PULARGE_INTEGER lpTotalNumberOfBytes total_number_of_bytes
    ** PULARGE_INTEGER lpTotalNumberOfFreeBytes total_number_of_free_bytes
