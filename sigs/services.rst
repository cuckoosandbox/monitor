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


OpenSCManagerW
==============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** LPWSTR lpMachineName machine_name
    ** LPWSTR lpDatabaseName database_name
    ** DWORD dwDesiredAccess desired_access


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


OpenServiceA
============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPCTSTR lpServiceName service_name
    ** DWORD dwDesiredAccess desired_access


OpenServiceW
============

Signature::

    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager service_manager_handle
    ** LPWSTR lpServiceName service_name
    ** DWORD dwDesiredAccess desired_access


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
