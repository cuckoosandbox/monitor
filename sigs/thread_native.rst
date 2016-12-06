Signature::

    * Calling convention: WINAPI
    * Category: process
    * Return value: NTSTATUS
    * Library: ntdll


NtCreateThread
==============

Signature::

    * Mode: exploit

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

    uint32_t pid = pid_from_process_handle(ProcessHandle);
    pipe("PROCESS:%d", pid);

Logging::

    u thread_name thread_name
    i process_identifier pid

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }

    free_unicode_buffer(thread_name);


NtCreateThreadEx
================

Signature::

    * Prune: resolve

Parameters::

    ** PHANDLE hThread thread_handle
    ** ACCESS_MASK DesiredAccess access
    ** POBJECT_ATTRIBUTES ObjectAttributes thread_name
    ** HANDLE ProcessHandle process_handle
    ** LPTHREAD_START_ROUTINE lpStartAddress function_address
    ** PVOID lpParameter parameter
    ** BOOL CreateSuspended suspended
    ** LONG StackZeroBits stack_zero_bits
    *  LONG SizeOfStackCommit
    *  LONG SizeOfStackReserve
    *  PVOID lpBytesBuffer

Pre::

    uint32_t pid = pid_from_process_handle(ProcessHandle);
    pipe("PROCESS:%d", pid);

Logging::

    i process_identifier pid

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

Post::

    free_unicode_buffer(thread_name);


NtGetContextThread
==================

Signature::

    * Mode: exploit

Parameters::

    ** HANDLE ThreadHandle thread_handle
    *  LPCONTEXT Context


NtSetContextThread
==================

Signature::

    * Mode: exploit

Parameters::

    ** HANDLE ThreadHandle thread_handle
    *  const CONTEXT *Context

Middle::

    bson registers;
    bson_init(&registers);
    bson_append_start_object(&registers, "registers");

    // TODO What about WOW64 processes?
    if(Context != NULL) {
    #if __x86_64__
        bson_append_long(&registers, "rax", Context->Rax);
        bson_append_long(&registers, "rcx", Context->Rcx);
        bson_append_long(&registers, "rdx", Context->Rdx);
        bson_append_long(&registers, "rbx", Context->Rbx);
        bson_append_long(&registers, "rsp", Context->Rsp);
        bson_append_long(&registers, "rbp", Context->Rbp);
        bson_append_long(&registers, "rsi", Context->Rsi);
        bson_append_long(&registers, "rdi", Context->Rdi);
        bson_append_long(&registers, "r8",  Context->R8);
        bson_append_long(&registers, "r9",  Context->R9);
        bson_append_long(&registers, "r10", Context->R10);
        bson_append_long(&registers, "r11", Context->R11);
        bson_append_long(&registers, "r12", Context->R12);
        bson_append_long(&registers, "r13", Context->R13);
        bson_append_long(&registers, "r14", Context->R14);
        bson_append_long(&registers, "r15", Context->R15);
        bson_append_long(&registers, "rip", Context->Rip);
    #else
        bson_append_int(&registers, "eax", Context->Eax);
        bson_append_int(&registers, "ecx", Context->Ecx);
        bson_append_int(&registers, "edx", Context->Edx);
        bson_append_int(&registers, "ebx", Context->Ebx);
        bson_append_int(&registers, "esp", Context->Esp);
        bson_append_int(&registers, "ebp", Context->Ebp);
        bson_append_int(&registers, "esi", Context->Esi);
        bson_append_int(&registers, "edi", Context->Edi);
        bson_append_int(&registers, "eip", Context->Eip);
    #endif
    }

    bson_append_finish_object(&registers);
    bson_finish(&registers);

    uint32_t pid = pid_from_thread_handle(ThreadHandle);

Logging::

    i process_identifier pid
    z registers &registers

Post::

    pipe("PROCESS:%d", pid);
    sleep_skip_disable();
    bson_destroy(&registers);


NtSuspendThread
===============

Signature::

    * Mode: exploit

Parameters::

    ** HANDLE ThreadHandle thread_handle
    ** ULONG *PreviousSuspendCount previous_suspend_count

Ensure::

    PreviousSuspendCount


NtResumeThread
==============

Signature::

    * Mode: exploit

Parameters::

    ** HANDLE ThreadHandle thread_handle
    ** ULONG *SuspendCount suspend_count

Ensure::

    SuspendCount

Pre::

    uint32_t pid = pid_from_thread_handle(ThreadHandle);
    if(pid != get_current_process_id()) {
        pipe("PROCESS:%d", pid);
        pipe("DUMPMEM:%d", pid);
    }

Logging::

    i process_identifier pid

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

Signature::

    * Mode: exploit

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

Signature::

    * Mode: exploit

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
