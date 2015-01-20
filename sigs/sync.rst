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
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** BOOLEAN InitialOwner initial_owner

Flags::

    desired_access

Pre::

    wchar_t *mutant_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, mutant_name);

Logging::

    u mutant_name mutant_name
