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

    ** PHANDLE MutantHandle mutant_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes mutant_name
    ** BOOLEAN InitialOwner initial_owner

Flags::

    desired_access
