Signature::

    * Calling convention: WINAPI
    * Category: netapi
    * Library: netapi32


NetGetJoinInformation
=====================

Signature::

    * Return value: NET_API_STATUS

Parameters::

    ** LPCWSTR lpServer server
    *  LPWSTR *lpNameBuffer
    *  PNETSETUP_JOIN_STATUS BufferType

Ensure::

    lpNameBuffer

Logging::

    u name *lpNameBuffer


NetUserGetInfo
==============

Signature::

    * Is success: ret == 0
    * Return value: int

Parameters::

    ** LPCWSTR servername server_name
    ** LPCWSTR username username
    ** DWORD level level
    *  LPBYTE *bufptr


NetUserGetLocalGroups
=====================

Signature::

    * Return value: NET_API_STATUS

Parameters::

    ** LPCWSTR servername servername
    ** LPCWSTR username username
    ** DWORD level level
    ** DWORD flags flags
    *  LPBYTE *bufptr
    *  DWORD prefmaxlen
    *  LPDWORD entriesread
    *  LPDWORD totalentries


NetShareEnum
============

Signature::

    * Return value: NET_API_STATUS

Parameters::

    ** LPWSTR servername servername
    ** DWORD level level
    *  LPBYTE *bufptr
    *  DWORD prefmaxlen
    *  LPDWORD entriesread
    *  LPDWORD totalentries
    *  LPDWORD resume_handle
