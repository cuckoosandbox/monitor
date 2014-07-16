Signature::

    * Calling convention: WINAPI
    * Category: system


SetWindowsHookExA
=================

Signature::

    * Return value: HHOOK

Parameters::

    ** int idHook hook_identifier
    ** HOOKPROC lpfn callback_function
    ** HINSTANCE hMod module_address
    ** DWORD dwThreadId thread_identifier


SetWindowsHookExW
=================

Signature::

    * Return value: HHOOK

Parameters::

    ** int idHook hook_identifier
    ** HOOKPROC lpfn callback_function
    ** HINSTANCE hMod module_address
    ** DWORD dwThreadId thread_identifier


UnhookWindowsHookEx
===================

Signature::

    * Return value: BOOL

Parameters::

    ** HHOOK hhk hook_handle


LdrLoadDll
==========

Signature::

    * Return value: NTSTATUS

Parameters::

    ** PWCHAR PathToFile filepath
    ** ULONG Flags flags
    *  PUNICODE_STRING ModuleFileName
    ** PHANDLE ModuleHandle module_address

Pre::

    COPY_UNICODE_STRING(library, ModuleFileName);

Logging::

    o module_name &library


LdrGetDllHandle
===============

Signature::

    * Return value: NTSTATUS

Parameters::

    *  PWORD pwPath
    *  PVOID Unused
    ** PUNICODE_STRING ModuleFileName module_name
    ** PHANDLE pHModule module_address


LdrGetProcedureAddress
======================

Signature::

    * Return value: NTSTATUS

Parameters::

    ** HMODULE ModuleHandle module_address
    ** PANSI_STRING FunctionName function_name
    ** WORD Ordinal ordinal
    ** PVOID *FunctionAddress function_address


ExitWindowsEx
=============

Signature::

    * Return value: BOOL

Parameters::

    ** UINT uFlags flags
    ** DWORD dwReason reason


IsDebuggerPresent
=================

Signature::

    * Return value: BOOL


LookupPrivilegeValueW
=====================

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpSystemName system_name
    ** LPWSTR lpName privilege_name
    *  PLUID lpLuid


NtClose
=======

Signature::

    * Return value: NTSTATUS

Parameters::

    HANDLE Handle handle

Post::

    if(NT_SUCCESS(ret)) {
        file_close(Handle);
    }
