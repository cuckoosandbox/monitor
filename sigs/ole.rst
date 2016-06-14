Signature::

    * Calling convention: WINAPI
    * Category: ole
    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT


CoCreateInstance
================

Parameters::

    ** REFCLSID rclsid clsid
    *  LPUNKNOWN pUnkOuter
    ** DWORD dwClsContext class_context
    ** REFIID riid iid
    *  LPVOID *ppv

Interesting::

    b sizeof(CLSID), rclsid
    i class_context
    b sizeof(IID), riid

Post::

    ole_enable_hooks(rclsid);


OleInitialize
=============

Parameters::

    *  LPVOID pvReserved


CoInitializeEx
==============

Parameters::

    *  LPVOID pvReserved
    ** DWORD dwCoInit options


CoUninitialize
==============


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
    *  DWORD dwCount
    *  MULTI_QI *pResults

Pre::

    bson b; char index[8], clsid[64];
    bson_init(&b);

    bson_append_start_array(&b, "iid");

    MULTI_QI *multi_qi = pResults;
    for (uint32_t idx = 0; idx < dwCount; idx++, multi_qi++) {
        our_snprintf(index, sizeof(index), "%d", idx++);
        clsid_to_string(copy_ptr(&multi_qi->pIID), clsid);
        log_string(&b, index, clsid, our_strlen(clsid));
    }

    bson_append_finish_array(&b);
    bson_finish(&b);

Logging::

    z iid &b

Post::

    ole_enable_hooks(rclsid);
    bson_destroy(&b);


CoGetClassObject
================

Parameters::

    ** REFCLSID rclsid clsid
    ** DWORD dwClsContext class_context
    *  COSERVERINFO *pServerInfo
    ** REFIID riid iid
    *  LPVOID *ppv

Post::

    ole_enable_hooks(rclsid);


OleConvertOLESTREAMToIStorage
=============================

Parameters::

    *  LPOLESTREAM lpolestream
    *  IStorage *pstg
    *  const DVTARGETDEVICE *ptd

Middle::

    void *buf = NULL; uintptr_t len = 0;

    #if !__x86_64__
    if(lpolestream != NULL) {
        buf = copy_ptr(copy_ptr((uint8_t *) lpolestream + 8));
        len = copy_uint32((uint8_t *) lpolestream + 12);
    }
    #endif

Logging::

    !b ole2 len, buf
