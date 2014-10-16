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

    COPY_UNICODE_STRING(module_name, ModuleFileName);
    library_from_unicode_string(ModuleFileName, library, sizeof(library));

Logging::

    O module_name &module_name

Post::

    if(NT_SUCCESS(ret)) {
        monitor_hook(library);
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

    COPY_UNICODE_STRING(module_name, ModuleFileName);

Logging::

    O module_name &module_name


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

Parameters::

    ** HANDLE Handle handle

Post::

    if(NT_SUCCESS(ret)) {
        dropped_close(Handle);
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
