Signature::

    * Calling convention: WINAPI
    * Category: ole
    * Library: ole32


CoCreateInstance
================

Signature::

    * Return value: HRESULT

Parameters::

    ** REFCLSID rclsid
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

Signature::

    * Return value: HRESULT

Parameters::

    *  LPVOID pvReserved


CoInitializeEx
==============

Signature::

    * Return value: HRESULT

Parameters::

    *  LPVOID pvReserved
    ** DWORD dwCoInit options


CoInitializeSecurity
====================

Signature::

    * Return value: HRESULT

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
