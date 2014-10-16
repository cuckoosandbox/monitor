Signature::

    * Calling convention: WINAPI
    * Category: process


CreateProcessInternalW
======================

Signature::

    * Library: kernel32
    * Return value: BOOL
    * Special: true

Parameters::

    *  LPVOID lpUnknown1
    *  LPWSTR lpApplicationName
    ** LPWSTR lpCommandLine command_line
    *  LPSECURITY_ATTRIBUTES lpProcessAttributes
    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    *  BOOL bInheritHandles
    *  DWORD dwCreationFlags
    *  LPVOID lpEnvironment
    ** LPWSTR lpCurrentDirectory current_directory
    *  LPSTARTUPINFO lpStartupInfo
    *  LPPROCESS_INFORMATION lpProcessInformation
    *  LPVOID lpUnknown2

Ensure::

    lpProcessInformation

Pre::

    // Ensure the CREATE_SUSPENDED flag is set when calling
    // the original function.
    DWORD creation_flags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpApplicationName, filepath);

Logging::

    u filepath filepath
    l creation_flags creation_flags
    i process_identifier lpProcessInformation->dwProcessId
    i thread_identifier lpProcessInformation->dwThreadId
    i process_handle lpProcessInformation->hProcess
    i thread_handle lpProcessInformation->hThread

Post::

    if(ret != FALSE) {
        pipe("PROCESS:%d,%d",
            lpProcessInformation->dwProcessId,
            lpProcessInformation->dwThreadId);

        // If the CREATE_SUSPENDED flag was not set then we have to resume
        // the main thread ourselves.
        if((creation_flags & CREATE_SUSPENDED) == 0) {
            ResumeThread(lpProcessInformation->hThread);
        }

        sleep_skip_disable();
    }

ExitProcess
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** UINT uExitCode status_code


ShellExecuteExW
===============

Signature::

    * Library: shell32
    * Return value: BOOL

Parameters::

    *  SHELLEXECUTEINFOW *pExecInfo

Ensure::

    pExecInfo

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(pExecInfo->lpFile, filepath);

Logging::

    u filepath filepath
    u parameters pExecInfo->lpParameters
    l show_type pExecInfo->nShow


ReadProcessMemory
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess process_handle
    ** LPCVOID lpBaseAddress base_address
    *  LPVOID lpBuffer
    *  SIZE_T nSize
    *  SIZE_T *lpNumberOfBytesRead

Ensure::

    lpNumberOfBytesRead

Logging::

    B buffer lpNumberOfBytesRead, lpBuffer


WriteProcessMemory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess process_handle
    ** LPVOID lpBaseAddress base_address
    *  LPCVOID lpBuffer
    *  SIZE_T nSize
    *  SIZE_T *lpNumberOfBytesWritten

Ensure::

    lpNumberOfBytesWritten

Logging::

    B buffer lpNumberOfBytesWritten, lpBuffer


VirtualProtectEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess process_handle
    ** LPVOID lpAddress base_address
    ** SIZE_T dwSize size
    ** DWORD flNewProtect protection
    *  PDWORD lpflOldProtect


VirtualFreeEx
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess process_handle
    ** LPVOID lpAddress base_address
    ** SIZE_T dwSize size
    ** DWORD dwFreeType free_type


system
======

Signature::

    * Is success: ret == 0
    * Library: msvcrt
    * Return value: int

Parameters::

    ** const char *command


CreateToolhelp32Snapshot
========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwFlags flags
    ** DWORD th32ProcessID process_identifier


Process32FirstW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPPROCESSENTRY32W lppe


Process32NextW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPPROCESSENTRY32W lppe


Module32FirstW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPMODULEENTRY32W lpme


Module32NextW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPMODULEENTRY32W lpme
