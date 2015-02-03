Signature::

    * Calling convention: WINAPI
    * Category: crypto


CryptAcquireContextA
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV *phProv crypto_handle
    ** LPCSTR szContainer container
    ** LPCSTR szProvider provider
    ** DWORD dwProvType provider_type
    ** DWORD dwFlags flags


CryptAcquireContextW
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV *phProv crypto_handle
    ** LPCWSTR szContainer container
    ** LPCWSTR szProvider provider
    ** DWORD dwProvType provider_type
    ** DWORD dwFlags flags


CryptProtectData
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    *  DATA_BLOB *pDataIn
    ** LPCWSTR szDataDescr description
    *  DATA_BLOB *pOptionalEntropy
    *  PVOID pvReserved
    *  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    *  DWORD dwFlags
    *  DATA_BLOB *pDataOut

Ensure::

    pDataIn

Prelog::

    b buffer pDataIn->cbData, pDataIn->pbData


CryptUnprotectData
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    *  DATA_BLOB *pDataIn
    *  LPWSTR *ppszDataDescr
    *  DATA_BLOB *pOptionalEntropy
    *  PVOID pvReserved
    *  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    *  DWORD dwFlags
    *  DATA_BLOB *pDataOut

Ensure::

    pDataOut
    pOptionalEntropy

Logging::

    u description ppszDataDescr != NULL ? *ppszDataDescr : NULL
    b entropy pOptionalEntropy->cbData, pOptionalEntropy->pbData
    b buffer pDataOut->cbData, pDataOut->pbData


CryptProtectMemory
==================

Signature::

    * Library: crypt32
    * Minimum: Windows Vista
    * Return value: BOOL

Parameters::

    *  LPVOID pData
    *  DWORD cbData
    ** DWORD dwFlags flags

Prelog::

    b buffer cbData, pData


CryptUnprotectMemory
====================

Signature::

    * Library: crypt32
    * Minimum: Windows Vista
    * Return value: BOOL

Parameters::

    *  LPVOID pData
    *  DWORD cbData
    ** DWORD dwFlags flags

Logging::

    b buffer cbData, pData


CryptDecrypt
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey key_handle
    ** HCRYPTHASH hHash hash_handle
    ** BOOL Final final
    ** DWORD dwFlags flags
    *  BYTE *pbData
    *  DWORD *pdwDataLen

Logging::

    B buffer *pdwDataLen, pbData


CryptEncrypt
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey key_handle
    ** HCRYPTHASH hHash hash_handle
    ** BOOL Final final
    ** DWORD dwFlags flags
    *  BYTE *pbData
    *  DWORD *pdwDataLen
    *  DWORD dwBufLen

Logging::

    b buffer dwBufLen, pbData


CryptHashData
=============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTHASH hHash hash_handle
    *  BYTE *pbData
    *  DWORD dwDataLen
    ** DWORD dwFlags flags

Logging::

    b buffer dwDataLen, pbData


CryptDecodeMessage
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    *  DWORD dwMsgTypeFlags
    *  PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    *  PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    *  DWORD dwSignerIndex
    *  const BYTE *pbEncodedBlob
    *  DWORD cbEncodedBlob
    *  DWORD dwPrevInnerContentType
    *  DWORD *pdwMsgType
    *  DWORD *pdwInnerContentType
    *  BYTE *pbDecoded
    *  DWORD *pcbDecoded
    *  PCCERT_CONTEXT *ppXchgCert
    *  PCCERT_CONTEXT *ppSignerCert

Logging::

    B buffer pcbDecoded, pbDecoded


CryptDecryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    *  PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    *  const BYTE *pbEncryptedBlob
    *  DWORD cbEncryptedBlob
    *  BYTE *pbDecrypted
    *  DWORD *pcbDecrypted
    *  PCCERT_CONTEXT *ppXchgCert

Logging::

    B buffer pcbDecrypted, pbDecrypted


CryptEncryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara
    * DWORD cRecipientCert
    * PCCERT_CONTEXT rgpRecipientCert[]
    * const BYTE *pbToBeEncrypted
    * DWORD cbToBeEncrypted
    * BYTE *pbEncryptedBlob
    * DWORD *pcbEncryptedBlob

Prelog::

    b buffer cbToBeEncrypted, pbToBeEncrypted


CryptHashMessage
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    *  PCRYPT_HASH_MESSAGE_PARA pHashPara
    *  BOOL fDetachedHash
    *  DWORD cToBeHashed
    *  const BYTE *rgpbToBeHashed[]
    *  DWORD rgcbToBeHashed[]
    *  BYTE *pbHashedBlob
    *  DWORD *pcbHashedBlob
    *  BYTE *pbComputedHash
    *  DWORD *pcbComputedHash

Pre::

    uint32_t length = 0;
    for (uint32_t idx = 0; idx < cToBeHashed; idx++) {
        length += rgcbToBeHashed[idx];
    }

    uint8_t *buf = mem_alloc(length);
    if(buf != NULL) {
        for (uint32_t idx = 0, offset = 0; idx < cToBeHashed; idx++) {
            memcpy(&buf[offset], rgpbToBeHashed[idx], rgcbToBeHashed[idx]);
            offset += rgcbToBeHashed[idx];
        }
    }

Logging::

    b buffer length, buf

Post::

    mem_free(buf);


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


CryptExportKey
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey crypto_handle
    ** HCRYPTKEY hExpKey crypto_export_handle
    ** DWORD dwBlobType blob_type
    ** DWORD dwFlags flags
    *  BYTE *pbData
    *  DWORD *pdwDataLen

Logging::

    B buffer pdwDataLen, pbData


CryptGenKey
===========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV hProv provider_handle
    ** ALG_ID Algid algorithm_identifier
    ** DWORD dwFlags flags
    ** HCRYPTKEY *phKey crypto_handle

Flags::

    algorithm_identifier


CryptCreateHash
===============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV hProv provider_handle
    ** ALG_ID Algid algorithm_identifier
    ** HCRYPTKEY hKey crypto_handle
    ** DWORD dwFlags flags
    ** HCRYPTHASH *phHash hash_handle

Flags::

    algorithm_identifier
