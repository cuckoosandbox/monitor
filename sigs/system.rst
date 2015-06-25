Signature::

    * Calling convention: WINAPI
    * Category: system


SetWindowsHookExA
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    ** int idHook hook_identifier
    ** HOOKPROC lpfn callback_function
    ** HINSTANCE hMod module_address
    ** DWORD dwThreadId thread_identifier

Flags::

    hook_identifier

Interesting::

    i hook_identifier
    i thread_identifier


SetWindowsHookExW
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    ** int idHook hook_identifier
    ** HOOKPROC lpfn callback_function
    ** HINSTANCE hMod module_address
    ** DWORD dwThreadId thread_identifier

Flags::

    hook_identifier

Interesting::

    i hook_identifier
    i thread_identifier


UnhookWindowsHookEx
===================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HHOOK hhk hook_handle


LdrLoadDll
==========

Signature::

    * Callback: init
    * Library: ntdll
    * Return value: NTSTATUS
    * Special: true

Parameters::

    *  PWCHAR PathToFile
    ** ULONG Flags flags
    *  PUNICODE_STRING ModuleFileName
    ** PHANDLE ModuleHandle module_address

Pre::

    char library[MAX_PATH];
    wchar_t *module_name = extract_unicode_string(ModuleFileName);
    library_from_unicode_string(ModuleFileName, library, sizeof(library));

Logging::

    u module_name module_name

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        hook_library(library);
    }

    free_unicode_buffer(module_name);


LdrUnloadDll
============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS
    * Special: true

Parameters::

    ** HANDLE ModuleHandle module_address

Pre::

    MEMORY_BASIC_INFORMATION_CROSS mbi;

    memset(&mbi, 0, sizeof(mbi));
    virtual_query(ModuleHandle, &mbi);

    unhook_detect_disable();

Middle::

    // If the module address is not readable anymore then the module got
    // unhooked and thus we have to notify the unhook detection monitoring.
    if(NT_SUCCESS(ret) != FALSE &&
            page_is_readable((const uint8_t *) mbi.AllocationBase) == 0) {
        unhook_detect_remove_dead_regions();
    }

    unhook_detect_enable();


LdrGetDllHandle
===============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    *  PWORD pwPath
    *  PVOID Unused
    *  PUNICODE_STRING ModuleFileName
    ** PHANDLE pHModule module_address

Pre::

    wchar_t *module_name = extract_unicode_string(ModuleFileName);

Logging::

    u module_name module_name

Post::

    free_unicode_buffer(module_name);


LdrGetProcedureAddress
======================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** HMODULE ModuleHandle module_address
    ** PANSI_STRING FunctionName function_name
    ** WORD Ordinal ordinal
    ** PVOID *FunctionAddress function_address


ExitWindowsEx
=============

Signature::

    * Library: user32
    * Prelog: instant
    * Return value: BOOL

Parameters::

    ** UINT uFlags flags
    ** DWORD dwReason reason


IsDebuggerPresent
=================

Signature::

    * Library: kernel32
    * Return value: BOOL


LookupPrivilegeValueW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpSystemName system_name
    ** LPWSTR lpName privilege_name
    *  PLUID lpLuid


NtDuplicateObject
=================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS
    * Special: true

Parameters::

    ** HANDLE SourceProcessHandle source_process_handle
    ** HANDLE SourceHandle source_handle
    ** HANDLE TargetProcessHandle target_process_handle
    ** HANDLE *TargetHandle target_handle
    ** ACCESS_MASK DesiredAccess desired_access
    ** ULONG HandleAttributes handle_attributes
    ** ULONG Options options

Logging::

    i source_process_identifier pid_from_process_handle(SourceProcessHandle)
    i target_process_identifier pid_from_process_handle(TargetProcessHandle)

Post::

    uintptr_t source_pid = pid_from_process_handle(SourceProcessHandle);
    uintptr_t target_pid = pid_from_process_handle(TargetProcessHandle);
    if(NT_SUCCESS(ret) != FALSE &&
            source_pid == get_current_process_id() &&
            target_pid == get_current_process_id()) {
        if(is_ignored_object_handle(SourceHandle) != 0) {
            ignored_object_add(*TargetHandle);
        }
    }


NtClose
=======

Signature::

    * Library: ntdll
    * Return value: NTSTATUS
    * Special: true

Parameters::

    ** HANDLE Handle handle

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        ignored_object_remove(Handle);
    }


GetSystemInfo
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    *  LPSYSTEM_INFO lpSystemInfo

Logging::

    i processor_count lpSystemInfo->dwNumberOfProcessors


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    *  LPSYSTEM_INFO lpSystemInfo

Logging::

    i processor_count lpSystemInfo->dwNumberOfProcessors


SetErrorMode
============

Signature::

    * Is success: 1
    * Library: kernel32
    * Return value: UINT

Parameters::

    ** UINT uMode mode

Flags::

    mode


NtLoadDriver
============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    *  PUNICODE_STRING DriverServiceName

Pre::

    wchar_t *driver_service_name = extract_unicode_string(DriverServiceName);

Logging::

    u driver_service_name driver_service_name

Post::

    free_unicode_buffer(driver_service_name);


NtUnloadDriver
==============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    *  PUNICODE_STRING DriverServiceName

Pre::

    wchar_t *driver_service_name = extract_unicode_string(DriverServiceName);

Logging::

    u driver_service_name driver_service_name

Post::

    free_unicode_buffer(driver_service_name);


GetAsyncKeyState
================

Signature::

    * Is success: 1
    * Library: user32
    * Return value: SHORT

Parameters::

    ** int vKey key_code


GetKeyboardState
================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    *  PBYTE lpKeyState


GetKeyState
===========

Signature::

    * Is success: 1
    * Library: user32
    * Return value: SHORT

Parameters::

    ** int nVirtKey key_code


SendNotifyMessageA
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HWND hWnd window_handle
    ** UINT uMsg message
    *  WPARAM wParam
    *  LPARAM lParam

Pre::

    unsigned long pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = GetWindowThreadProcessId(hWnd, &pid);
    pipe("PROCESS2:%d,%d", pid, tid);

Logging::

    l process_identifier (uintptr_t) pid


SendNotifyMessageW
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HWND hWnd window_handle
    ** UINT uMsg message
    *  WPARAM wParam
    *  LPARAM lParam

Pre::

    unsigned long pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = GetWindowThreadProcessId(hWnd, &pid);
    pipe("PROCESS2:%d,%d", pid, tid);

Logging::

    l process_identifier (uintptr_t) pid


RtlCompressBuffer
=================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** USHORT CompressionFormatAndEngine format
    *  PUCHAR UncompressedBuffer
    ** ULONG UncompressedBufferSize input_size
    *  PUCHAR CompressedBuffer
    *  ULONG CompressedBufferSize
    *  ULONG UncompressedChunkSize
    ** PULONG FinalCompressedSize output_size
    *  PVOID WorkSpace

Prelog::

    !b uncompressed UncompressedBufferSize, UncompressedBuffer

Logging::

    !B compressed FinalCompressedSize, CompressedBuffer


RtlDecompressBuffer
===================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** USHORT CompressionFormat format
    *  PUCHAR UncompressedBuffer
    *  ULONG UncompressedBufferSize
    *  PUCHAR CompressedBuffer
    ** ULONG CompressedBufferSize input_size
    ** PULONG FinalUncompressedSize output_size

Prelog::

    !b compressed CompressedBufferSize, CompressedBuffer

Logging::

    !B uncompressed FinalUncompressedSize, UncompressedBuffer


RtlDecompressFragment
=====================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** USHORT CompressionFormat format
    *  PUCHAR UncompressedFragment
    *  ULONG UncompressedFragmentSize
    *  PUCHAR CompressedBuffer
    ** ULONG CompressedBufferSize input_size
    ** ULONG FragmentOffset offset
    ** PULONG FinalUncompressedSize output_size
    *  PVOID WorkSpace

Prelog::

    !b compressed CompressedBufferSize, CompressedBuffer

Logging::

    !B uncompressed FinalUncompressedSize, UncompressedFragment


RtlDispatchException
====================

Signature::

    * Callback: addr
    * Is success: 1
    * Library: ntdll
    * Logging: no
    * Return value: void *
    * Special: true

Parameters::

    *  EXCEPTION_RECORD *ExceptionRecord
    *  CONTEXT *Context

Pre::

    uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;

    count = stacktrace(Context, addrs, RETADDRCNT);
    log_exception(Context, ExceptionRecord, addrs, count);
