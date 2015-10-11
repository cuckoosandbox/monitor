Signature::

    * Calling convention: WINAPI
    * Category: ole
    * Library: ole32
    * Return value: HRESULT


CoCreateInstance
================

Parameters::

    ** REFCLSID rclsid clsid
    *  LPUNKNOWN pUnkOuter
    ** DWORD dwClsContext class_context
    ** REFIID riid
    *  LPVOID *ppv

Interesting::

    b sizeof(CLSID), rclsid
    i class_context
    b sizeof(IID), riid


OleInitialize
=============

Parameters::

    *  LPVOID pvReserved


CoInitializeEx
==============

Parameters::

    *  LPVOID pvReserved
    ** DWORD dwCoInit options


CoInitializeSecurity
====================

Parameters::

    *  PSECURITY_DESCRIPTOR pSecDesc
    *  LONG cAuthSvc
    *  SOLE_AUTHENTICATION_SERVICE *asAuthSvc
    *  void *pReserved1
    *  DWORD dwAuthnLevel
    *  DWORD dwImpLevel
    *  void *pAuthList
    *  DWORD dwCapabilities
    *  void *pReserved3


CoCreateInstanceEx
==================

Parameters::

    ** REFCLSID rclsid clsid
    *  IUnknown *punkOuter
    ** DWORD dwClsCtx class_context
    *  COSERVERINFO *pServerInfo
    ** DWORD dwCount count
    *  MULTI_QI *pResults


CoGetClassObject
================

Parameters::

    ** REFCLSID rclsid clsid
    ** DWORD dwClsContext class_context
    *  COSERVERINFO *pServerInfo
    ** REFIID riid
    *  LPVOID *ppv
