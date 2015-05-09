Signature::

    * Calling convention: WINAPI
    * Category: certificate


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
