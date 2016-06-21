Signature::

    * Calling convention: WINAPI
    * Category: process
    * Library: kernel32


CreateJobObjectW
================

Signature::

    * Return value: HANDLE

Parameters::

    *  LPSECURITY_ATTRIBUTES lpJobAttributes
    ** LPCTSTR lpName

Logging::

    p job_handle ret


SetInformationJobObject
=======================

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hJob job_handle
    ** JOBOBJECTINFOCLASS JobObjectInfoClass information_class
    *  LPVOID lpJobObjectInfo
    *  DWORD cbJobObjectInfoLength

Logging::

    b buf (uintptr_t) cbJobObjectInfoLength, lpJobObjectInfo


AssignProcessToJobObject
========================

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hJob job_handle
    ** HANDLE hProcess process_handle

Logging::

    i process_identifier pid_from_process_handle(hProcess)
