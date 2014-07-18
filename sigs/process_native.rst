Signature::

    * Calling convention: WINAPI
    * Category: process
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateProcess
===============

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes filepath
    *  HANDLE ParentProcess
    *  BOOLEAN InheritObjectTable
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        disable_sleep_skip();
    }


NtCreateProcessEx
=================

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes filepath
    *  HANDLE ParentProcess
    *  ULONG Flags
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort
    *  BOOLEAN InJob

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        disable_sleep_skip();
    }


NtCreateUserProcess
===================

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** PHANDLE ThreadHandle thread_handle
    ** ACCESS_MASK ProcessDesiredAccess desired_access_process
    ** ACCESS_MASK ThreadDesiredAccess desired_access_thread
    ** POBJECT_ATTRIBUTES ProcessObjectAttributes process_name
    ** POBJECT_ATTRIBUTES ThreadObjectAttributes thread_name
    ** ULONG ProcessFlags flags_process
    ** ULONG ThreadFlags flags_thread
    *  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    *  PPS_CREATE_INFO CreateInfo
    *  PPS_ATTRIBUTE_LIST AttributeList

Logging::

    o filepath &ProcessParameters->ImagePathName
    o command_line &ProcessParameters->CommandLine

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d,%d", pid_from_process_handle(*ProcessHandle),
            pid_from_thread_handle(*ThreadHandle));
        disable_sleep_skip();
    }


RtlCreateUserProcess
====================

Parameters::

    ** PUNICODE_STRING ImagePath filepath
    ** ULONG ObjectAttributes flags
    *  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    *  PSECURITY_DESCRIPTOR ProcessSecurityDescriptor
    *  PSECURITY_DESCRIPTOR ThreadSecurityDescriptor
    *  HANDLE ParentProcess
    *  BOOLEAN InheritHandles
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort
    *  PRTL_USER_PROCESS_INFORMATION ProcessInformation

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d,%d",
            pid_from_process_handle(ProcessInformation->ProcessHandle),
            pid_from_thread_handle(ProcessInformation->ThreadHandle));
        disable_sleep_skip();
    }


NtOpenProcess
=============

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes object_attributes
    *  PCLIENT_ID ClientId

Pre::

    uintptr_t pid = 0;
    if(ClientId != NULL) {
        pid = (uintptr_t) ClientId->UniqueProcess;
    }

Logging::

    i process_identifier pid


NtTerminateProcess
==================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** NTSTATUS ExitStatus status_code


NtCreateSection
===============

Parameters::

    ** PHANDLE SectionHandle section_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes object_attributes
    *  PLARGE_INTEGER MaximumSize
    ** ULONG SectionPageProtection protection
    *  ULONG AllocationAttributes
    ** HANDLE FileHandle file_handle


NtMakeTemporaryObject
=====================

Parameters::

    ** HANDLE ObjectHandle handle


NtMakePermanentObject
=====================

Parameters::

    ** HANDLE ObjectHandle handle


NtOpenSection
=============

Parameters::

    ** PHANDLE SectionHandle section_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** POBJECT_ATTRIBUTES ObjectAttributes object_attributes


NtUnmapViewOfSection
====================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** PVOID BaseAddress base_address


NtAllocateVirtualMemory
=======================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** PVOID *BaseAddress
    *  ULONG_PTR ZeroBits
    ** PSIZE_T RegionSize region_size
    ** ULONG AllocationType allocation_type
    ** ULONG Protect protection


NtReadVirtualMemory
===================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** LPCVOID BaseAddress base_address
    *  LPVOID Buffer
    *  ULONG NumberOfBytesToRead
    *  PULONG NumberOfBytesReaded

Ensure::

    NumberOfBytesReaded

Logging::

    B buffer NumberOfBytesReaded, Buffer


NtWriteVirtualMemory
====================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** LPVOID BaseAddress base_address
    *  LPCVOID Buffer
    *  ULONG NumberOfBytesToWrite
    *  ULONG *NumberOfBytesWritten

Ensure::

    NumberOfBytesWritten

Logging::

    B buffer NumberOfBytesWritten, Buffer


NtProtectVirtualMemory
======================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** PVOID *BaseAddress base_address
    *  PULONG NumberOfBytesToProtect
    ** ULONG NewAccessProtection protection
    *  PULONG OldAccessProtection


NtFreeVirtualMemory
===================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** PVOID *BaseAddress base_address
    ** PULONG RegionSize size
    ** ULONG FreeType free_type


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
