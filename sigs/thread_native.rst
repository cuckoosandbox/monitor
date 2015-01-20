Signature::

    * Calling convention: WINAPI
    * Category: thread
    * Return value: NTSTATUS
    * Library: ntdll


NtCreateThread
==============

Parameters::

    ** PHANDLE ThreadHandle thread_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** HANDLE ProcessHandle process_handle
    *  PCLIENT_ID ClientId
    *  PCONTEXT ThreadContext
    *  PINITIAL_TEB InitialTeb
    ** BOOLEAN CreateSuspended suspended

Pre::

    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, thread_name);

    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

Logging::

    u thread_name thread_name

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


NtCreateThreadEx
================

Signature::

    * Minimum: Windows 7

Parameters::

    ** PHANDLE hThread thread_handle
    ** ACCESS_MASK DesiredAccess access
    ** PVOID ObjectAttributes thread_name
    ** HANDLE ProcessHandle process_handle
    ** LPTHREAD_START_ROUTINE lpStartAddress function_address
    ** PVOID lpParameter parameter
    ** BOOL CreateSuspended suspended
    ** LONG StackZeroBits
    *  LONG SizeOfStackCommit
    *  LONG SizeOfStackReserve
    *  PVOID lpBytesBuffer

Pre::

    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


NtOpenThread
============

Parameters::

    ** PHANDLE ThreadHandle thread_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PCLIENT_ID ClientId

Pre::

    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, thread_name);

Logging::

    u thread_name thread_name
    i process_identifier pid_from_thread_handle(ThreadHandle)


NtGetContextThread
==================

Parameters::

    ** HANDLE ThreadHandle thread_handle
    *  LPCONTEXT Context


NtSetContextThread
==================

Parameters::

    ** HANDLE ThreadHandle thread_handle
    *  const CONTEXT *Context

Post::

    pipe("PROCESS:%d", pid_from_thread_handle(ThreadHandle));
    sleep_skip_disable();


NtSuspendThread
===============

Parameters::

    ** HANDLE ThreadHandle thread_handle
    ** ULONG *PreviousSuspendCount previous_suspend_count

Ensure::

    PreviousSuspendCount


NtResumeThread
==============

Parameters::

    ** HANDLE ThreadHandle thread_handle
    ** ULONG *SuspendCount suspend_count

Ensure::

    SuspendCount

Pre::

    pipe("PROCESS:%d", pid_from_thread_handle(ThreadHandle));

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


NtTerminateThread
=================

Parameters::

    ** HANDLE ThreadHandle thread_handle
    ** NTSTATUS ExitStatus status_code


RtlCreateUserThread
===================

Parameters::

    ** HANDLE ProcessHandle process_handle
    *  PSECURITY_DESCRIPTOR SecurityDescriptor
    ** BOOLEAN CreateSuspended suspended
    *  ULONG StackZeroBits
    *  PULONG StackReserved
    *  PULONG StackCommit
    ** PVOID StartAddress function_address
    ** PVOID StartParameter parameter
    ** PHANDLE ThreadHandle thread_handle
    *  PCLIENT_ID ClientId

Pre::

    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


NtQueueApcThread
================

Parameters::

    ** HANDLE ThreadHandle thread_handle
    *  PIO_APC_ROUTINE ApcRoutine
    ** PVOID ApcRoutineContext function_address
    ** PIO_STATUS_BLOCK ApcStatusBlock parameter
    *  ULONG ApcReserved

Pre::

    pipe("PROCESS:%d", pid_from_thread_handle(ThreadHandle));

Logging::

    i process_identifier pid_from_thread_handle(ThreadHandle)

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }
