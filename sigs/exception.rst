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
    * Prune: resolve
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
    * Prune: resolve
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
    * Prune: resolve
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
    * Mode: exploit
    * Library: ntdll
    * Logging: no
    * Return value: void *
    * Special: true

Parameters::

    *  EXCEPTION_RECORD *ExceptionRecord
    *  CONTEXT *Context

Pre::

    uint32_t exception_code = 0;
    if(ExceptionRecord != NULL) {
        exception_code = ExceptionRecord->ExceptionCode;
    }

    uintptr_t pc = 0;
    #if __x86_64__
    pc = Context->Rip;
    #else
    pc = Context->Eip;
    #endif

    // Is this exception within our monitor?
    if(exception_code == STATUS_ACCESS_VIOLATION &&
            pc >= g_monitor_start && pc < g_monitor_end) {
        copy_return();
    }

    // Is this exception address whitelisted? This is the case for the
    // IsBadReadPtr function where access violations are expected.
    if(exception_code == STATUS_ACCESS_VIOLATION &&
            is_exception_address_whitelisted(pc) == 0) {
        // TODO Should we do something here?
        // For now we'll just ignore this code path.
    }
    // Ignore exceptions that are caused by calling OutputDebugString().
    else if(is_exception_code_whitelisted(exception_code) == 0) {
        uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
        count = stacktrace(Context, addrs, RETADDRCNT);
        log_exception(Context, ExceptionRecord, addrs, count);
    }


_RtlRaiseException
==================

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
