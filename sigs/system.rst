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
        monitor_hook(library);
    }


LdrUnloadDll
============

Signature::

    * Library: ntdll
    * Return value: NTSTATUS
    * Special: true

Parameters::

    ** HANDLE ModuleHandle module_address

Pre::

    MEMORY_BASIC_INFORMATION mbi;

    memset(&mbi, 0, sizeof(mbi));
    virtual_query(ModuleHandle, &mbi);

    unhook_detect_disable();

Middle::

    // If the module address is not readable anymore then the module got
    // unhooked and thus we have to notify the unhook detection monitoring.
    if(NT_SUCCESS(ret) != FALSE &&
            page_is_readable(mbi.AllocationBase) == 0) {
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
        dropped_close(Handle);
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


NetUserGetInfo
==============

Signature::

    * Is success: ret == 0
    * Library: netapi32
    * Return value: int

Parameters::

    ** LPCWSTR servername server_name
    ** LPCWSTR username username
    ** DWORD level level
    *  LPBYTE *bufptr


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
