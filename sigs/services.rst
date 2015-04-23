Signature::

    * Calling convention: WINAPI
    * Category: services
    * Library: advapi32


OpenSCManagerA
==============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** LPCTSTR lpMachineName machine_name
    ** LPCTSTR lpDatabaseName database_name
    ** DWORD dwDesiredAccess desired_access

Interesting::

    s machine_name
    s database_name
    i desired_access


OpenSCManagerW
==============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** LPWSTR lpMachineName machine_name
    ** LPWSTR lpDatabaseName database_name
    ** DWORD dwDesiredAccess desired_access

Interesting::

    u machine_name
    u database_name
    i desired_access


CreateServiceA
==============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPCTSTR lpServiceName service_name
    ** LPCTSTR lpDisplayName display_name
    ** DWORD dwDesiredAccess desired_access
    ** DWORD dwServiceType service_type
    ** DWORD dwStartType start_type
    ** DWORD dwErrorControl error_control
    *  LPCTSTR lpBinaryPathName
    *  LPCTSTR lpLoadOrderGroup
    *  LPDWORD lpdwTagId
    *  LPCTSTR lpDependencies
    ** LPCTSTR lpServiceStartName service_start_name
    ** LPCTSTR lpPassword password

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathA(lpBinaryPathName, filepath);

Interesting::

    s service_name
    s display_name
    i desired_access
    i service_type
    i start_type
    i error_control
    u filepath
    s service_start_name
    s password

Logging::

    u filepath filepath

Post::

    free_unicode_buffer(filepath);


CreateServiceW
==============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPWSTR lpServiceName service_name
    ** LPWSTR lpDisplayName display_name
    ** DWORD dwDesiredAccess desired_access
    ** DWORD dwServiceType service_type
    ** DWORD dwStartType start_type
    ** DWORD dwErrorControl error_control
    *  LPWSTR lpBinaryPathName
    *  LPWSTR lpLoadOrderGroup
    *  LPDWORD lpdwTagId
    *  LPWSTR lpDependencies
    ** LPWSTR lpServiceStartName service_start_name
    ** LPWSTR lpPassword password

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpBinaryPathName, filepath);

Interesting::

    u service_name
    u display_name
    i desired_access
    i service_type
    i start_type
    i error_control
    u filepath
    u service_start_name
    u password

Logging::

    u filepath filepath

Post::

    free_unicode_buffer(filepath);


OpenServiceA
============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPCTSTR lpServiceName service_name
    ** DWORD dwDesiredAccess desired_access

Interesting::

    s service_name
    i desired_access


OpenServiceW
============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPWSTR lpServiceName service_name
    ** DWORD dwDesiredAccess desired_access

Interesting::

    u service_name
    i desired_access


StartServiceA
=============

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService service_handle
    * DWORD dwNumServiceArgs
    * LPCTSTR *lpServiceArgVectors

Logging::

    a arguments dwNumServiceArgs, lpServiceArgVectors


StartServiceW
=============

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService service_handle
    *  DWORD dwNumServiceArgs
    *  LPWSTR *lpServiceArgVectors

Logging::

    A arguments dwNumServiceArgs, lpServiceArgVectors


ControlService
==============

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService service_handle
    ** DWORD dwControl control_code
    *  LPSERVICE_STATUS lpServiceStatus


DeleteService
=============

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService service_handle
