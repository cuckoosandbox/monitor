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
    ** DWORD dwFlags flags
    *  DATA_BLOB *pDataOut

Ensure::

    pDataIn

Prelog::

    !b buffer (uintptr_t) copy_uint32(&pDataIn->cbData), copy_ptr(&pDataIn->pbData)


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
    ** DWORD dwFlags flags
    *  DATA_BLOB *pDataOut

Ensure::

    pDataOut
    pOptionalEntropy

Logging::

    u description ppszDataDescr != NULL ? copy_ptr(ppszDataDescr) : NULL
    b entropy (uintptr_t) copy_uint32(&pOptionalEntropy->cbData), copy_ptr(&pOptionalEntropy->pbData)
    !b buffer (uintptr_t) copy_uint32(&pDataOut->cbData), copy_ptr(&pDataOut->pbData)


CryptProtectMemory
==================

Signature::

    * Library: crypt32
    * Prune: resolve
    * Return value: BOOL

Parameters::

    *  LPVOID pData
    *  DWORD cbData
    ** DWORD dwFlags flags

Prelog::

    !b buffer (uintptr_t) cbData, pData


CryptUnprotectMemory
====================

Signature::

    * Library: crypt32
    * Prune: resolve
    * Return value: BOOL

Parameters::

    *  LPVOID pData
    *  DWORD cbData
    ** DWORD dwFlags flags

Logging::

    !b buffer (uintptr_t) cbData, pData


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

Ensure::

    pdwDataLen

Logging::

    !b buffer (uintptr_t) copy_uint32(pdwDataLen), pbData


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

Prelog::

    !b buffer (uintptr_t) dwBufLen, pbData


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

    !b buffer (uintptr_t) dwDataLen, pbData


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

Ensure::

    pcbDecoded

Logging::

    !b buffer (uintptr_t) copy_uint32(pcbDecoded), pbDecoded


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

Ensure::

    pcbDecrypted

Logging::

    !b buffer (uintptr_t) copy_uint32(pcbDecrypted), pbDecrypted


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

    !b buffer (uintptr_t) cbToBeEncrypted, pbToBeEncrypted


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

    uintptr_t length = 0;
    for (uint32_t idx = 0; idx < cToBeHashed; idx++) {
        length += copy_uint32(&rgcbToBeHashed[idx]);
    }

    uint8_t *buf = mem_alloc(length);
    if(buf != NULL) {
        for (uint32_t idx = 0, offset = 0; idx < cToBeHashed; idx++) {
            copy_bytes(
                &buf[offset], copy_ptr(&rgpbToBeHashed[idx]),
                copy_uint32(&rgcbToBeHashed[idx])
            );
            offset += copy_uint32(&rgcbToBeHashed[idx]);
        }
    }

Logging::

    !b buffer length, buf

Post::

    mem_free(buf);


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

Ensure::

    pdwDataLen

Logging::

    b buffer (uintptr_t) copy_uint32(pdwDataLen), pbData


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

Middle::

    uint8_t keybuf[256]; DWORD keysize = 0;

    Old_advapi32_CryptExportKey(
        *phKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keysize
    );
    Old_advapi32_CryptExportKey(
        *phKey, 0, PLAINTEXTKEYBLOB, 0, keybuf, &keysize
    );

Logging::

    b key (uintptr_t) keysize, keybuf


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


CryptDecodeObjectEx
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** DWORD dwCertEncodingType encoding_type
    *  LPCSTR lpszStructType
    *  const BYTE *pbEncoded
    *  DWORD cbEncoded
    ** DWORD dwFlags flags
    *  PCRYPT_DECODE_PARA pDecodePara
    *  void *pvStructInfo
    *  DWORD *pcbStructInfo

Ensure::

    pcbStructInfo

Pre::

    char number[10], *struct_type;

    int_or_strA(&struct_type, lpszStructType, number);

Middle::

    void *buf = pvStructInfo;

    if((dwFlags & CRYPT_ENCODE_ALLOC_FLAG) != 0) {
        buf = copy_ptr(pvStructInfo);
    }

Logging::

    s struct_type struct_type
    !b buffer (uintptr_t) copy_uint32(pcbStructInfo), buf


PRF
===

Signature::

    * Callback: module
    * Library: ncrypt
    * Mode: dumptls
    * Prune: resolve
    * Return value: NTSTATUS

Parameters::

    *  void *unk1
    *  uintptr_t unk2
    *  uint8_t *buf1
    *  uintptr_t buf1_length
    ** const char *type
    *  uint32_t type_length
    *  uint8_t *buf2
    *  uint32_t buf2_length
    *  uint8_t *buf3
    *  uint32_t buf3_length

Middle::

    uintptr_t master_secret_length = 0, random_length = 0;
    uint8_t *master_secret = NULL, *client_random = NULL;
    uint8_t *server_random = NULL;

    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};

    if(type_length == 13 && strcmp(type, "key expansion") == 0 &&
            buf2_length == 64) {
        master_secret_length = buf1_length;
        master_secret = buf1;

        random_length = 32;
        server_random = buf2;
        client_random = buf2 + random_length;

        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, master_secret, master_secret_length);
    }

Logging::

    s client_random client_random_repr
    s server_random server_random_repr
    s master_secret master_secret_repr


Ssl3GenerateKeyMaterial
=======================

Signature::

    * Callback: module
    * Library: ncrypt
    * Mode: dumptls
    * Prune: resolve
    * Return value: NTSTATUS

Parameters::

    *  uintptr_t unk1
    *  uint8_t *secret
    *  uintptr_t secret_length
    *  uint8_t *seed
    *  uintptr_t seed_length
    *  void *unk2
    *  uintptr_t unk3

Middle::

    uintptr_t random_length = 32;
    uint8_t *client_random = seed;
    uint8_t *server_random = seed + random_length;

    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};

    if(seed_length == 64 && secret_length == 48) {
        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, secret, secret_length);
    }

Logging::

    s client_random client_random_repr
    s server_random server_random_repr
    s master_secret master_secret_repr


EncryptMessage
==============

Signature::

    * Library: secur32
    * Return value: SECURITY_STATUS

Parameters::

    ** PCtxtHandle phContext context_handle
    ** ULONG fQOP qop
    *  PSecBufferDesc pMessage
    ** ULONG MessageSeqNo number

Pre::

    uint8_t *buf = NULL; uintptr_t length = 0;

    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
        buf = memdup(buf, length);
    }

Logging::

    !b buffer length, buf

Post::

    mem_free(buf);


DecryptMessage
==============

Signature::

    * Library: secur32
    * Return value: SECURITY_STATUS

Parameters::

    ** PCtxtHandle phContext context_handle
    *  PSecBufferDesc pMessage
    ** ULONG MessageSeqNo number
    ** PULONG pfQOP qop

Middle::

    uint8_t *buf = NULL; uintptr_t length = 0;

    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
    }

Logging::

    !b buffer length, buf
