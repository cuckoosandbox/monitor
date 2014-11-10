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
    * Minimum: Windows 7
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
    * Minimum: Windows 7
    * Return value: ULONG

Parameters::

    *  PVOID VectoredHandlerHandle

Interesting::

    p VectoredHandlerHandle
