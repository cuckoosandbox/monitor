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


OutputDebugStringA
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTR lpOutputString string


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
    * Mode: exploit
    * Return value: NTSTATUS
    * Special: true

Parameters::

    *  PWCHAR PathToFile
    ** PULONG Flags flags
    *  PUNICODE_STRING ModuleFileName
    ** PHANDLE ModuleHandle module_address

Pre::

    char library[MAX_PATH];
    wchar_t *module_name = extract_unicode_string_unistr(ModuleFileName);
    library_from_unicode_string(ModuleFileName, library, sizeof(library));

Logging::

    u module_name module_name
    s basename library
    i stack_pivoted exploit_is_stack_pivoted()

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        hook_library(library, NULL);
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

    char library[MAX_PATH+1];
    library_from_unicodez(get_module_file_name(ModuleHandle),
        library, sizeof(library));

Middle::

    // If the module address is not readable anymore then the module got
    // unhooked and thus we have to notify the unhook detection monitoring.
    if(NT_SUCCESS(ret) != FALSE &&
            page_is_readable((const uint8_t *) mbi.AllocationBase) == 0) {
        unhook_detect_remove_dead_regions();
    }

    unhook_detect_enable();

Logging::

   s library library

Post::

    if(range_is_readable(ModuleHandle, 0x1000) == 0) {
        unhook_library(library, ModuleHandle);
    }


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

    wchar_t *module_name = extract_unicode_string_unistr(ModuleFileName);

Middle::

    if(NT_SUCCESS(ret) == FALSE && pHModule != NULL) {
        *pHModule = NULL;
    }

Logging::

    u module_name module_name
    i stack_pivoted exploit_is_stack_pivoted()

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

Pre::

    char library[MAX_PATH+1];

    library_from_unicodez(get_module_file_name(ModuleHandle),
        library, sizeof(library));

Logging::

    s module library


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

Middle::

    uint32_t processor_count = lpSystemInfo->dwNumberOfProcessors;

    // The PEB either contains the real number of processors or the number
    // of processors that we spoofed into it.
    lpSystemInfo->dwNumberOfProcessors = get_peb()->NumberOfProcessors;

Logging::

    i processor_count processor_count


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    *  LPSYSTEM_INFO lpSystemInfo

Middle::

    uint32_t processor_count = lpSystemInfo->dwNumberOfProcessors;

    // The PEB either contains the real number of processors or the number
    // of processors that we spoofed into it.
    lpSystemInfo->dwNumberOfProcessors = get_peb()->NumberOfProcessors;

Logging::

    i processor_count processor_count


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

    wchar_t *driver_service_name =
        extract_unicode_string_unistr(DriverServiceName);

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

    wchar_t *driver_service_name =
        extract_unicode_string_unistr(DriverServiceName);

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

    uint32_t pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);

Logging::

    i process_identifier pid


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

    uint32_t pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);

Logging::

    i process_identifier pid


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

Logging::

    !B uncompressed FinalUncompressedSize, UncompressedFragment


GlobalMemoryStatus
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    *  LPMEMORYSTATUS lpBuffer

Middle::

    lpBuffer->dwTotalPhys += g_extra_virtual_memory;
    lpBuffer->dwTotalVirtual += g_extra_virtual_memory;


GlobalMemoryStatusEx
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    *  LPMEMORYSTATUSEX lpBuffer

Middle::

    lpBuffer->ullTotalPhys += g_extra_virtual_memory;
    lpBuffer->ullTotalVirtual += g_extra_virtual_memory;


NtQuerySystemInformation
========================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    ** SYSTEM_INFORMATION_CLASS SystemInformationClass information_class
    *  PVOID SystemInformation
    *  ULONG SystemInformationLength
    *  PULONG ReturnLength

Flags::

    information_class


NtShutdownSystem
================

Signature::

    * Library: ntdll
    * Prelog: instant
    * Return value: NTSTATUS

Parameters::

    ** SHUTDOWN_ACTION Action action

Flags::

    action
