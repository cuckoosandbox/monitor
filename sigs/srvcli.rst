Signature::

    * Calling convention: WINAPI
    * Category: netapi
    * Library: srvcli


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
