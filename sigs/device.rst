Signature::

    * Calling convention: WINAPI
    * Category: device


DeviceIoControl
===============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hDevice device_handle
    ** DWORD dwIoControlCode control_code
    *  LPVOID lpInBuffer
    *  DWORD nInBufferSize
    *  LPVOID lpOutBuffer
    *  DWORD nOutBufferSize
    *  LPDWORD lpBytesReturned
    *  LPOVERLAPPED lpOverlapped

Ensure::

    * lpBytesReturned

Prelog::

    b input_buffer nInBufferSize, lpInBuffer

Logging::

    B output_buffer lpBytesReturned, lpOutBuffer
