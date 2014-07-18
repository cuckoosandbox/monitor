Signature::

    * Calling convention: WINAPI
    * Category: misc


WriteConsoleA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput console_handle
    *  const VOID *lpBuffer
    *  DWORD nNumberOfCharsToWrite
    *  LPDWORD lpNumberOfCharsWritten
    *  LPVOID lpReseverd

Logging::

    S buffer lpNumberOfCharsWritten, lpBuffer


WriteConsoleW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput console_handle
    *  const VOID *lpBuffer
    *  DWORD nNumberOfCharsToWrite
    *  LPDWORD lpNumberOfCharsWritten
    *  LPVOID lpReseverd

Logging::

    U buffer lpNumberOfCharsWritten, lpBuffer


GetSystemMetrics
================

Signature::

    * Is success: ret != 0
    * Library: user32
    * Return value: int

Parameters::

    ** int nIndex index


GetCursorPos
============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    *  LPPOINT lpPoint

Logging::

    l x lpPoint != NULL ? lpPoint->x : 0
    l y lpPoint != NULL ? lpPoint->y : 0
