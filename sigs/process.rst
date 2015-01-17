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
    ** BOOL bInheritHandles inherit_handles
    *  DWORD dwCreationFlags
    *  LPVOID lpEnvironment
    ** LPWSTR lpCurrentDirectory current_directory
    *  LPSTARTUPINFO lpStartupInfo
    *  LPPROCESS_INFORMATION lpProcessInformation
    *  LPVOID lpUnknown2

Flags::

    creation_flags creation_flags

Ensure::

    lpProcessInformation

Pre::

    // Ensure the CREATE_SUSPENDED flag is set when calling
    // the original function.
    DWORD creation_flags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpApplicationName, filepath);

Interesting::

    u filepath
    u command_line
    i inherit_handles
    i creation_flags
    u current_directory

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
    * Prelog: instant

Parameters::

    ** UINT uExitCode status_code

Interesting::

    i status_code


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
    if(pExecInfo->lpFile != NULL) {
        // In case it's a relative path we'll just stick to it.
        wcsncpy(filepath, pExecInfo->lpFile, MAX_PATH_W);

        // If this is not a relative path then we resolve the full path.
        if(lstrlenW(pExecInfo->lpFile) > 2 && pExecInfo->lpFile[1] == ':' &&
                pExecInfo->lpFile[2] == '\\') {
            path_get_full_pathW(pExecInfo->lpFile, filepath);
        }
    }

Interesting::

    u filepath
    i pExecInfo->fMask
    u pExecInfo->lpVerb
    u pExecInfo->lpFile
    u pExecInfo->lpParameters
    u pExecInfo->lpDirectory
    i pExecInfo->nShow
    u pExecInfo->lpClass
    i pExecInfo->dwHotKey

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

Flags::

    protection


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

Interesting::

    s command


CreateToolhelp32Snapshot
========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwFlags flags
    ** DWORD th32ProcessID process_identifier

Interesting::

    i flags
    i process_identifier


Process32FirstW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPPROCESSENTRY32W lppe

Logging::

    u process_name lppe->szExeFile
    i process_id lppe->th32ProcessID


Process32NextW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPPROCESSENTRY32W lppe

Logging::

    u process_name lppe->szExeFile
    i process_id lppe->th32ProcessID


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
