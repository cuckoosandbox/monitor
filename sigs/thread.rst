Signature::

    * Calling convention: WINAPI
    * Category: process
    * Library: kernel32


CreateThread
============

Signature::

    * Return value: HANDLE

Parameters::

    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize stack_size
    ** LPTHREAD_START_ROUTINE lpStartAddress function_address
    ** LPVOID lpParameter parameter
    ** DWORD dwCreationFlags flags
    ** LPDWORD lpThreadId thread_identifier

Ensure::

    lpThreadId

Post::

    if(ret != NULL) {
        sleep_skip_disable();
    }


CreateRemoteThread
==================

Signature::

    * Return value: HANDLE

Parameters::

    ** HANDLE hProcess process_handle
    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize stack_size
    ** LPTHREAD_START_ROUTINE lpStartAddress function_address
    ** LPVOID lpParameter parameter
    ** DWORD dwCreationFlags flags
    ** LPDWORD lpThreadId thread_identifier

Pre::

    pipe("PROCESS:%d", pid_from_process_handle(hProcess));

Post::

    if(ret != NULL) {
        sleep_skip_disable();
    }


CreateRemoteThreadEx
====================

Signature::

    * Prune: resolve
    * Return value: HANDLE

Parameters::

    ** HANDLE hProcess process_handle
    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize stack_size
    ** LPTHREAD_START_ROUTINE lpStartAddress function_address
    ** LPVOID lpParameter parameter
    ** DWORD dwCreationFlags flags
    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
    ** LPDWORD lpThreadId thread_identifier


Thread32First
=============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPTHREADENTRY32 lpte


Thread32Next
============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot snapshot_handle
    *  LPTHREADENTRY32 lpte
