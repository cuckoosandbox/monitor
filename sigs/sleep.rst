Signature::

    * Calling convention: WINAPI
    * Category: synchronisation


NtDelayExecution
================

Signature::

    * Library: ntdll
    * Mode: exploit
    * Return value: NTSTATUS

Parameters::

    *  BOOLEAN Alertable
    *  PLARGE_INTEGER DelayInterval

Ensure::

    DelayInterval

Pre::

    int64_t milliseconds = -DelayInterval->QuadPart / 10000;
    int skipped = sleep_skip(DelayInterval);

Logging::

    q milliseconds milliseconds
    i skipped skipped


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


GetSystemTimeAsFileTime
=======================

Signature::

    * Is success: 1
    * Library: kernel32
    * Return value: void

Parameters::

    *  LPFILETIME lpSystemTimeAsFileTime

Post::

    sleep_apply_filetime(lpSystemTimeAsFileTime);


NtQuerySystemTime
=================

Signature::

    * Library: ntdll
    * Logging: no
    * Return value: NTSTATUS

Parameters::

    *  PLARGE_INTEGER SystemTime

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        SystemTime->QuadPart += sleep_skipped();
    }


timeGetTime
===========

Signature::

    * Is success: 1
    * Library: winmm
    * Return value: DWORD

Post::

    ret += sleep_skipped() / 10000;
