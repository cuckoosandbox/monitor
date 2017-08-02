Signature::

    * Calling convention: WINAPI
    * Category: synchronisation

NtOpenEvent
===========

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** PHANDLE EventHandle event_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Flags::

    desired_access

Pre::

    wchar_t *event_name = NULL;
    if(ObjectAttributes != NULL) {
        event_name = extract_unicode_string_unistr(ObjectAttributes->ObjectName);
    }

Logging::

    u event_name event_name

Post::

    free_unicode_buffer(event_name);


NtCreateMutant
==============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

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
        mutant_name = extract_unicode_string_unistr(ObjectAttributes->ObjectName);
    }

Logging::

    u mutant_name mutant_name

Post::

    free_unicode_buffer(mutant_name);


NtOpenMutant
============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** PHANDLE MutantHandle mutant_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Flags::

    desired_access

Pre::

    wchar_t *mutant_name = NULL;
    if(ObjectAttributes != NULL) {
        mutant_name = extract_unicode_string_unistr(ObjectAttributes->ObjectName);
    }

Logging::

    u mutant_name mutant_name

Post::

    free_unicode_buffer(mutant_name);
