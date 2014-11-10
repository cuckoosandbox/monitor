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
