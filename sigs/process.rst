Signature::

    * Calling convention: WINAPI
    * Category: process
    * Library: kernel32


CreateProcessInternalW
======================

Signature::

    * Return value: BOOL

Parameters::

    *  LPVOID lpUnknown1
    ** LPWSTR lpApplicationName filepath
    ** LPWSTR lpCommandLine command_line
    *  LPSECURITY_ATTRIBUTES lpProcessAttributes
    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    *  BOOL bInheritHandles
    ** DWORD dwCreationFlags creation_flags
    *  LPVOID lpEnvironment
    ** LPWSTR lpCurrentDirectory current_directory
    *  LPSTARTUPINFO lpStartupInfo
    *  LPPROCESS_INFORMATION lpProcessInformation
    *  LPVOID lpUnknown2

Ensure::

    lpProcessInformation

Logging::

    i process_identifier lpProcessInformation->dwProcessId
    i thread_identifier lpProcessInformation->dwThreadId
    i process_handle lpProcessInformation->hProcess
    i thread_handle lpProcessInformation->hThread


ExitProcess
===========

Signature::

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

Logging::

    u filepath pExecInfo->lpFile
    u parameters pExecInfo->lpParameters
    l show_type pExecInfo->nShow


ReadProcessMemory
=================

Signature::

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
