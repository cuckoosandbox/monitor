Signature::

    * Calling convention: WINAPI
    * Category: misc


IWbemServices_ExecQuery
=======================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** ULONG lFlags flags
    *  IWbemContext *pCtx
    *  IEnumWbemClassObject **ppEnum


IWbemServices_ExecQueryAsync
============================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemObjectSink *pResponseHandler
