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
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  HANDLE ParentProcess
    *  BOOLEAN InheritObjectTable
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort

Pre::

    COPY_OBJECT_ATTRIBUTES(filepath, ObjectAttributes);

Logging::

    x filepath &filepath

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        sleep_skip_disable();
    }


NtCreateProcessEx
=================

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  HANDLE ParentProcess
    *  ULONG Flags
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort
    *  BOOLEAN InJob

Pre::

    COPY_OBJECT_ATTRIBUTES(filepath, ObjectAttributes);

Logging::

    x filepath &filepath

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        sleep_skip_disable();
    }


NtCreateUserProcess
===================

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** PHANDLE ThreadHandle thread_handle
    ** ACCESS_MASK ProcessDesiredAccess desired_access_process
    ** ACCESS_MASK ThreadDesiredAccess desired_access_thread
    *  POBJECT_ATTRIBUTES ProcessObjectAttributes
    *  POBJECT_ATTRIBUTES ThreadObjectAttributes
    ** ULONG ProcessFlags flags_process
    ** ULONG ThreadFlags flags_thread
    *  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    *  PPS_CREATE_INFO CreateInfo
    *  PPS_ATTRIBUTE_LIST AttributeList

Pre::

    COPY_OBJECT_ATTRIBUTES(process_name, ProcessObjectAttributes);
    COPY_OBJECT_ATTRIBUTES(thread_name, ThreadObjectAttributes);

Logging::

    x process_name &process_name
    x thread_name &thread_name
    O filepath &ProcessParameters->ImagePathName
    O command_line &ProcessParameters->CommandLine

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d,%d", pid_from_process_handle(*ProcessHandle),
            pid_from_thread_handle(*ThreadHandle));
        sleep_skip_disable();
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
        sleep_skip_disable();
    }


NtOpenProcess
=============

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PCLIENT_ID ClientId

Pre::

    COPY_OBJECT_ATTRIBUTES(object_attributes, ObjectAttributes);

    uintptr_t pid = 0;
    if(ClientId != NULL) {
        pid = (uintptr_t) ClientId->UniqueProcess;
    }

Logging::

    i process_identifier pid
    x object_attributes &object_attributes


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
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PLARGE_INTEGER MaximumSize
    ** ULONG SectionPageProtection protection
    *  ULONG AllocationAttributes
    ** HANDLE FileHandle file_handle

Pre::

    COPY_OBJECT_ATTRIBUTES(section_name, ObjectAttributes);

Logging::

    x section_name &section_name


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
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    COPY_OBJECT_ATTRIBUTES(section_name, ObjectAttributes);

Logging::

    x section_name &section_name


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


NtMapViewOfSection
==================

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

Post::

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));
        sleep_skip_disable();
    }
