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

    wchar_t *mutant_name = NULL;
    if(ObjectAttributes != NULL) {
        mutant_name = extract_unicode_string(ObjectAttributes->ObjectName);
    }

Logging::

    u mutant_name mutant_name
