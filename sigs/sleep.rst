Signature::

    * Calling convention: WINAPI
    * Category: sleep


NtDelayExecution
================

Signature::

    * Library: ntdll
    * Return value: NTSTATUS

Parameters::

    *  BOOLEAN Alertable
    *  PLARGE_INTEGER DelayInterval

Ensure::

    DelayInterval

Pre::

    const char *status = "Not skipped";
    if(sleep_skip(DelayInterval) != 0) {
        status = "Skipped";
    }

Logging::

    q milliseconds -DelayInterval->QuadPart / 10000
    s status status


GetLocalTime
============

Signature::

    * Library: kernel32
    * Logging: no
    * Return value: void

Parameters::

    *  LPSYSTEMTIME lpSystemTime

Post::

    sleep_apply_systemtime(lpSystemTime);


GetSystemTime
=============

Signature::

    * Library: kernel32
    * Logging: no
    * Return value: void

Parameters::

    *  LPSYSTEMTIME lpSystemTime

Post::

    sleep_apply_systemtime(lpSystemTime);


GetTickCount
============

Signature::

    * Is success: 1
    * Library: kernel32
    * Logging: no
    * Return value: DWORD

Post::

    ret += sleep_skipped() / 10000;


NtQuerySystemTime
=================

Signature::

    * Library: ntdll
    * Logging: no
    * Return value: NTSTATUS

Parameters::

    *  PLARGE_INTEGER SystemTime

Post::

    if(NT_SUCCESS(ret)) {
        SystemTime->QuadPart += sleep_skipped();
    }
