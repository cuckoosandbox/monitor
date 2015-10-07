Signature::

    * Calling convention: WINAPI
    * Category: certificate


CertOpenStore
=============

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    *  LPCSTR lpszStoreProvider
    ** DWORD dwMsgAndCertEncodingType encoding_type
    *  HCRYPTPROV hCryptProv
    ** DWORD dwFlags flags
    *  const void *pvPara

Pre::

    char number[10], *store_provider;

    int_or_strA(&store_provider, lpszStoreProvider, number);

Logging::

    s store_provider store_provider


CertOpenSystemStoreA
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    *  HCRYPTPROV hProv
    ** LPCTSTR szSubsystemProtocol store_name


CertOpenSystemStoreW
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    *  HCRYPTPROV hProv
    ** LPCWSTR szSubsystemProtocol store_name


CertControlStore
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** HCERTSTORE hCertStore cert_store
    ** DWORD dwFlags flags
    ** DWORD dwCtrlType control_type
    *  const void *pvCtrlPara


CertCreateCertificateContext
============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    ** DWORD dwCertEncodingType encoding
    *  const BYTE *pbCertEncoded
    *  DWORD cbCertEncoded

Logging::

    b certificate cbCertEncoded, pbCertEncoded
