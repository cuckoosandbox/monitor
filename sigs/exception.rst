Signature::

    * Calling convention: WINAPI
    * Category: exception


SetUnhandledExceptionFilter
===========================

Signature::

    * Is success: ret != NULL
    * Library: kernel32
    * Return value: LPTOP_LEVEL_EXCEPTION_FILTER

Parameters::

    *  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter

Interesting::

    p lpTopLevelExceptionFilter


RtlAddVectoredExceptionHandler
==============================

Signature::

    * Is success: 1
    * Library: ntdll
    * Return value: PVOID

Parameters::

    ** ULONG FirstHandler
    *  PVECTORED_EXCEPTION_HANDLER VectoredHandler

Interesting::

    p VectoredHandler
    i FirstHandler


RtlAddVectoredContinueHandler
=============================

Signature::

    * Is success: 1
    * Library: ntdll
    * Return value: PVOID

Parameters::

    ** ULONG FirstHandler
    *  PVECTORED_EXCEPTION_HANDLER VectoredHandler

Interesting::

    p VectoredHandler


RtlRemoveVectoredExceptionHandler
=================================

Signature::

    * Is success: 1
    * Library: ntdll
    * Return value: ULONG

Parameters::

    *  PVOID VectoredHandlerHandle

Interesting::

    p VectoredHandlerHandle


RtlRemoveVectoredContinueHandler
================================

Signature::

    * Is success: 1
    * Library: ntdll
    * Return value: ULONG

Parameters::

    *  PVOID VectoredHandlerHandle

Interesting::

    p VectoredHandlerHandle


RtlDispatchException
====================

Signature::

    * Callback: addr
    * Is success: 1
    * Library: ntdll
    * Logging: no
    * Return value: void *
    * Special: true

Parameters::

    *  EXCEPTION_RECORD *ExceptionRecord
    *  CONTEXT *Context

Pre::

    // uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
    // count = stacktrace(Context, addrs, RETADDRCNT);
    // log_exception(Context, ExceptionRecord, addrs, count);

    log_exception(Context, ExceptionRecord, NULL, 0);


RtlRaiseException
=================

Signature::

    * Is success: 1
    * Library: ntdll
    * Logging: no
    * Return value: void *
    * Special: true

Parameters::

    * EXCEPTION_RECORD *ExceptionRecord

Pre::

    // uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
    // count = stacktrace(NULL, addrs, RETADDRCNT);
    // log_exception(NULL, ExceptionRecord, addrs, count);

    log_exception(NULL, ExceptionRecord, NULL, 0);


_NtRaiseException
=================

Signature::

    * Is success: 1
    * Library: ntdll
    * Logging: no
    * Return value: NTSTATUS
    * Special: true

Parameters::

    * EXCEPTION_RECORD *ExceptionRecord
    * CONTEXT *Context
    * BOOLEAN HandleException

Pre::

    // uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
    // count = stacktrace(NULL, addrs, RETADDRCNT);
    // log_exception(Context, ExceptionRecord, addrs, count);

    log_exception(Context, ExceptionRecord, NULL, 0);
