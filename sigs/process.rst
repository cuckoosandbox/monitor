Signature::

    * Calling convention: WINAPI
    * Category: process


ZwMapViewOfSection
==================

Signature::

    * Return value: NTSTATUS

Parameters::

    ** HANDLE SectionHandle section_handle
    ** HANDLE ProcessHandle process_handle
    ** PVOID *BaseAddress base_address
    *  ULONG_PTR ZeroBits
    ** SIZE_T CommitSize commit_size
    ** PLARGE_INTEGER SectionOffset section_offset
    *  PSIZE_T ViewSize
    *  UINT InheritDisposition
    ** ULONG AllocationType allocation_type
    *  ULONG Win32Protect

Logging::

    P base_address BaseAddress

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));
        disable_sleep_skip();
    }
