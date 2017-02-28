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
    * Mode: exploit
    * Library: ntdll
    * Logging: no
    * Return value: BOOL
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

    #if EXPLOIT_GUARD_SUPPORT_ENABLED

    // Is this a guard page violation in one of our registered guard pages?
    if(exception_code == STATUS_GUARD_PAGE_VIOLATION) {
        int used = exploit_hotpatch_guard_page_referer(pc);

        if(Context->Dr7 == 0) {
            exploit_set_last_guard_page(
                (void *) ExceptionRecord->ExceptionInformation[1]
            );

            if(used < 0) {
                log_guardrw(ExceptionRecord->ExceptionInformation[1]);
                pipe("CRITICAL:Error instantiating Guard Page hotpatch");
                return TRUE;
            }

            Context->Dr0 = Context->Eip + used;
            Context->Dr7 = 1;
            return TRUE;
        }
        return TRUE;
    }

    // The hardware breakpoint triggers a single step exception.
    if(exception_code == STATUS_SINGLE_STEP && pc == Context->Dr0) {
        Context->Dr0 = 0;
        Context->Dr7 = 0;

        exploit_set_guard_page(exploit_get_last_guard_page());
        return TRUE;
    }

    #endif

    // Is this exception address whitelisted? This is the case for the
    // IsBadReadPtr function where access violations are expected.
    if(exception_code == STATUS_ACCESS_VIOLATION &&
            is_exception_address_whitelisted(pc) == 0) {
        // TODO Should we do something here?
        // For now we'll just ignore this code path.
    }
    // Ignore several exception codes such as the one caused by calling
    // OutputDebugString().
    else if(is_exception_code_whitelisted(exception_code) == 0) {
        uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
        count = stacktrace(Context, addrs, RETADDRCNT);
        log_exception(Context, ExceptionRecord, addrs, count, 0);
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
    // log_exception(NULL, ExceptionRecord, addrs, count, 0);

    log_exception(NULL, ExceptionRecord, NULL, 0, 0);


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
    // log_exception(Context, ExceptionRecord, addrs, count, 0);

    log_exception(Context, ExceptionRecord, NULL, 0, 0);
