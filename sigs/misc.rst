Signature::

    * Calling convention: WINAPI
    * Category: misc


WriteConsoleA
=============

Signature::

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

    * Return value: int
    * Is success: 1

Parameters::

    ** int nIndex index


GetCursorPos
============

Signature::

    * Return value: BOOL

Parameters::

    *  LPPOINT lpPoint

Logging::

    l x lpPoint != NULL ? lpPoint->x : 0
    l y lpPoint != NULL ? lpPoint->y : 0
