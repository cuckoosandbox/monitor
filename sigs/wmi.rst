Signature::

    * Callback: addr
    * Calling convention: WINAPI
    * Category: misc
    * Library: __wmi__
    * Mode: iexplore
    * Prune: resolve
    * Return value: HRESULT


IWbemServices_ExecQuery
=======================

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** ULONG lFlags flags
    *  IWbemContext *pCtx
    *  IEnumWbemClassObject **ppEnum


IWbemServices_ExecQueryAsync
============================

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemObjectSink *pResponseHandler
