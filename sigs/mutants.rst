Signature::

    * Calling convention: WINAPI
    * Category: synchronisation

NtCreateMutant
==============

Signature::

    * Is success: ret != 0
    * Library: ntdll
    * Return value: int

Parameters::

    ** PHANDLE MutantHandle
    *  ACCESS_MASK DesiredAccess
    ** POBJECT_ATTRIBUTES ObjectAttributes MutexName
    ** BOOLEAN InitialOwner
