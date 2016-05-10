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

    p service_handle ret
    u filepath filepath
    s filepath_r lpBinaryPathName

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

    p service_handle ret
    u filepath filepath
    u filepath_r lpBinaryPathName

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

Logging::

    p service_handle ret


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

Logging::

    p service_handle ret


StartServiceA
=============

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService service_handle
    *  DWORD dwNumServiceArgs
    *  LPCTSTR *lpServiceArgVectors

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


EnumServicesStatusA
===================

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager service_handle
    ** DWORD dwServiceType service_type
    ** DWORD dwServiceState service_status
    *  LPENUM_SERVICE_STATUS lpServices
    *  DWORD cbBufSize
    *  LPDWORD pcbBytesNeeded
    *  LPDWORD lpServicesReturned
    *  LPDWORD lpResumeHandle


EnumServicesStatusW
===================

Signature::

    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager service_handle
    ** DWORD dwServiceType service_type
    ** DWORD dwServiceState service_status
    *  LPENUM_SERVICE_STATUS lpServices
    *  DWORD cbBufSize
    *  LPDWORD pcbBytesNeeded
    *  LPDWORD lpServicesReturned
    *  LPDWORD lpResumeHandle


StartServiceCtrlDispatcherW
===========================

Signature::

    * Return value: BOOL

Parameters::

    *  const SERVICE_TABLE_ENTRYW *lpServiceTable

Pre::

    bson b, a; char index[10]; int idx = 0; SERVICE_TABLE_ENTRYW entry;
    bson_init(&b);
    bson_init(&a);

    bson_append_start_array(&b, "services");
    bson_append_start_array(&a, "addresses");

    const SERVICE_TABLE_ENTRYW *ptr = lpServiceTable;
    while (
        copy_bytes(&entry, ptr, sizeof(SERVICE_TABLE_ENTRYW)) == 0 &&
        entry.lpServiceProc != NULL
    ) {
        our_snprintf(index, sizeof(index), "%d", idx++);
        log_wstring(&b, index, entry.lpServiceName,
            copy_strlenW(entry.lpServiceName));

        log_intptr(&a, index, (intptr_t)(uintptr_t) entry.lpServiceProc);
    }

    bson_append_finish_array(&a);
    bson_append_finish_array(&b);
    bson_finish(&a);
    bson_finish(&b);

Logging::

    z addresses &a
    z services &b

Post::

    bson_destroy(&a);
    bson_destroy(&b);
