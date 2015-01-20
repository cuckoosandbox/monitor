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
    ** BOOLEAN InheritObjectTable inherit_handles
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort

Flags::

    desired_access

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Interesting::

    u filepath
    i desired_access
    i inherit_handles

Logging::

    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE) {
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
    ** ULONG Flags flags
    *  HANDLE SectionHandle
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort
    *  BOOLEAN InJob

Flags::

    desired_access

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Interesting::

    u filepath
    i desired_access
    i flags

Logging::

    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        sleep_skip_disable();
    }


NtCreateUserProcess
===================

Signature::

    * Minimum: Windows 7

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

Flags::

    desired_access_process
    desired_access_thread

Pre::

    wchar_t *process_name = get_unicode_buffer();
    path_get_full_path_objattr(ProcessObjectAttributes, process_name);

    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ThreadObjectAttributes, thread_name);

    wchar_t *filepath =
        extract_unicode_string(&ProcessParameters->ImagePathName);
    wchar_t *command_line =
        extract_unicode_string(&ProcessParameters->CommandLine);

Logging::

    u process_name process_name
    u thread_name thread_name
    u filepath filepath
    u command_line command_line

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d,%d", pid_from_process_handle(*ProcessHandle),
            tid_from_thread_handle(*ThreadHandle));
        sleep_skip_disable();
    }


RtlCreateUserProcess
====================

Parameters::

    *  PUNICODE_STRING ImagePath
    ** ULONG ObjectAttributes flags
    *  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    *  PSECURITY_DESCRIPTOR ProcessSecurityDescriptor
    *  PSECURITY_DESCRIPTOR ThreadSecurityDescriptor
    *  HANDLE ParentProcess
    ** BOOLEAN InheritHandles inherit_handles
    *  HANDLE DebugPort
    *  HANDLE ExceptionPort
    *  PRTL_USER_PROCESS_INFORMATION ProcessInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_unistr(ImagePath, filepath);

Interesting::

    u filepath
    i flags
    i inherit_handles

Logging::

    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d,%d",
            pid_from_process_handle(ProcessInformation->ProcessHandle),
            tid_from_thread_handle(ProcessInformation->ThreadHandle));
        sleep_skip_disable();
    }


NtOpenProcess
=============

Parameters::

    ** PHANDLE ProcessHandle process_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PCLIENT_ID ClientId

Flags::

    desired_access

Ensure::

    ClientId

Logging::

    l process_identifier (uintptr_t) ClientId->UniqueProcess


NtTerminateProcess
==================

Signature::

    * Prelog: instant

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

Flags::

    desired_access

Pre::

    wchar_t *section_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, section_name);

Logging::

    u section_name section_name


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

Flags::

    desired_access

Pre::

    wchar_t *section_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, section_name);

Logging::

    u section_name section_name


NtUnmapViewOfSection
====================

Parameters::

    ** HANDLE ProcessHandle process_handle
    ** PVOID BaseAddress base_address

Pre::

    MEMORY_BASIC_INFORMATION mbi; uintptr_t region_size = 0;
    if(VirtualQueryEx(ProcessHandle, BaseAddress, &mbi,
            sizeof(mbi)) == sizeof(mbi)) {
        region_size = mbi.RegionSize;
    }

Logging::

    i region_size region_size


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

Flags::

    protection


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
    ** PSIZE_T ViewSize view_size
    *  UINT InheritDisposition
    ** ULONG AllocationType allocation_type
    ** ULONG Win32Protect win32_protect

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));
        sleep_skip_disable();
    }
