Signature::

    * Calling convention: WINAPI
    * Category: network


URLDownloadToFileW
==================

Signature::

    * Library: urlmon
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  LPUNKNOWN pCaller
    ** LPWSTR szURL url
    *  LPWSTR szFileName
    *  DWORD dwReserved
    *  LPVOID lpfnCB

Interesting::

    u url
    u filepath

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(szFileName, filepath);

Logging::

    u filepath filepath
    u filepath_r szFileName
    i stack_pivoted exploit_is_stack_pivoted()

Post::

    if(ret == S_OK) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


InternetCrackUrlA
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    *  LPCSTR lpszUrl
    *  DWORD dwUrlLength
    ** DWORD dwFlags flags
    *  LPURL_COMPONENTSA lpUrlComponents

Pre::

    uint32_t length = dwUrlLength;
    if(length == 0 && lpszUrl != NULL) {
        length = copy_strlen(lpszUrl);
    }

Logging::

    S url length, lpszUrl


InternetCrackUrlW
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    *  LPCWSTR lpszUrl
    *  DWORD dwUrlLength
    ** DWORD dwFlags flags
    *  LPURL_COMPONENTSW lpUrlComponents

Pre::

    uint32_t length = dwUrlLength;
    if(length == 0 && lpszUrl != NULL) {
        length = copy_strlenW(lpszUrl);
    }

Logging::

    U url length, lpszUrl


InternetOpenA
=============

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** LPCTSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPCTSTR lpszProxyName proxy_name
    ** LPCTSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags

Interesting::

    s user_agent
    i access_type
    s proxy_name
    s proxy_bypass
    i flags


InternetOpenW
=============

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** LPWSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPWSTR lpszProxyName proxy_name
    ** LPWSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags

Interesting::

    u user_agent
    i access_type
    u proxy_name
    u proxy_bypass
    i flags


InternetConnectA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPCTSTR lpszServerName hostname
    ** INTERNET_PORT nServerPort port
    ** LPCTSTR lpszUsername username
    ** LPCTSTR lpszPassword password
    ** DWORD dwService service
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    s hostname
    i port
    s username
    s password
    i service
    i flags


InternetConnectW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPWSTR lpszServerName hostname
    ** INTERNET_PORT nServerPort port
    ** LPWSTR lpszUsername username
    ** LPWSTR lpszPassword password
    ** DWORD dwService service
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    u hostname
    i port
    u username
    u password
    i service
    i flags


InternetOpenUrlA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPCTSTR lpszUrl url
    *  LPCTSTR lpszHeaders
    *  DWORD dwHeadersLength
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Pre::

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

Interesting::

    s url
    S headers_length, lpszHeaders
    i flags

Logging::

    S headers headers_length, lpszHeaders


InternetOpenUrlW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet
    ** LPWSTR lpszUrl url
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Pre::

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

Interesting::

    u url
    U headers_length, lpszHeaders
    i flags

Logging::

    U headers headers_length, lpszHeaders


InternetQueryOptionA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle
    ** DWORD dwOption option
    *  LPVOID lpBuffer
    *  LPDWORD lpdwBufferLength

Flags::

    option


InternetSetOptionA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle
    ** DWORD dwOption option
    *  LPVOID lpBuffer
    *  DWORD dwBufferLength

Flags::

    option


HttpOpenRequestA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hConnect connect_handle
    ** LPCTSTR lpszVerb http_method
    ** LPCTSTR lpszObjectName path
    ** LPCTSTR lpszVersion http_version
    ** LPCTSTR lpszReferer referer
    *  LPCTSTR *lplpszAcceptTypes
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    s http_method
    s path
    s http_version
    s referer
    i flags


HttpOpenRequestW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hConnect connect_handle
    ** LPWSTR lpszVerb http_method
    ** LPWSTR lpszObjectName path
    ** LPWSTR lpszVersion http_version
    ** LPWSTR lpszReferer referer
    *  LPWSTR *lplpszAcceptTypes
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    u http_method
    u path
    u http_version
    u referer
    i flags


HttpSendRequestA
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPCTSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

Interesting::

    S dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    S headers headers_length, lpszHeaders
    b post_data (uintptr_t) dwOptionalLength, lpOptional


HttpSendRequestW
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

Interesting::

    U dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    U headers headers_length, lpszHeaders
    b post_data (uintptr_t) dwOptionalLength, lpOptional


InternetReadFile
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hFile request_handle
    *  LPVOID lpBuffer
    *  DWORD dwNumberOfBytesToRead
    *  LPDWORD lpdwNumberOfBytesRead

Ensure::

    lpdwNumberOfBytesRead

Logging::

    b buffer (uintptr_t) copy_uint32(lpdwNumberOfBytesRead), lpBuffer


InternetWriteFile
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hFile request_handle
    *  LPCVOID lpBuffer
    *  DWORD dwNumberOfBytesToWrite
    *  LPDWORD lpdwNumberOfBytesWritten

Ensure::

    lpdwNumberOfBytesWritten

Logging::

    b buffer (uintptr_t) copy_uint32(lpdwNumberOfBytesWritten), lpBuffer


InternetCloseHandle
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle


InternetGetConnectedState
=========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags flags
    *  DWORD dwReserved


InternetGetConnectedStateExA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags flags
    ** LPCSTR lpszConnectionName connection_name
    *  DWORD dwNameLen
    *  DWORD dwReserved


InternetGetConnectedStateExW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags flags
    ** LPWSTR lpszConnectionName connection_name
    *  DWORD dwNameLen
    *  DWORD dwReserved


InternetSetStatusCallback
=========================

Signature::

    * Is success: 1
    * Library: wininet
    * Return value: INTERNET_STATUS_CALLBACK

Parameters::

    ** HINTERNET hInternet internet_handle
    ** INTERNET_STATUS_CALLBACK lpfnInternetCallback callback


DeleteUrlCacheEntryA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrlName url


DeleteUrlCacheEntryW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPWSTR lpszUrlName url


DnsQuery_A
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PCSTR lpstrName hostname
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved

Interesting::

    s hostname
    i dns_type
    i options


DnsQuery_UTF8
=============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    *  LPBYTE lpstrName
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved

Interesting::

    s lpstrName
    i dns_type
    i options

Logging::

    s hostname lpstrName


DnsQuery_W
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PWSTR lpstrName hostname
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved

Interesting::

    u hostname
    i dns_type
    i options


getaddrinfo
===========

Signature::

    * Is success: ret == 0
    * Library: ws2_32
    * Return value: int

Parameters::

    ** PCSTR pNodeName hostname
    ** PCSTR pServiceName service_name
    *  const ADDRINFOA *pHints
    *  PADDRINFOA *ppResult

Interesting::

    s hostname
    s service_name


GetAddrInfoW
============

Signature::

    * Is success: ret == 0
    * Library: ws2_32
    * Return value: int

Parameters::

    ** PCWSTR pNodeName hostname
    ** PCWSTR pServiceName service_name
    *  const ADDRINFOW *pHints
    *  PADDRINFOW *ppResult

Interesting::

    u hostname
    u service_name


GetInterfaceInfo
================

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  PIP_INTERFACE_INFO pIfTable
    *  PULONG dwOutBufLen


GetAdaptersInfo
===============

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  PIP_ADAPTER_INFO pAdapterInfo
    *  PULONG pOutBufLen


GetAdaptersAddresses
====================

Signature::

    * Is success: ret == ERROR_SUCCESS
    * Library: iphlpapi
    * Return value: ULONG

Parameters::

    ** ULONG Family family
    ** ULONG Flags flags
    *  PVOID Reserved
    *  PIP_ADAPTER_ADDRESSES AdapterAddresses
    *  PULONG SizePointer


HttpQueryInfoA
==============

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    ** DWORD dwInfoLevel info_level
    *  LPVOID lpvBuffer
    *  LPDWORD lpdwBufferLength
    ** LPDWORD lpdwIndex index

Ensure::

    lpdwBufferLength

Logging::

    b buffer (uintptr_t) copy_uint32(lpdwBufferLength), lpvBuffer


ObtainUserAgentString
=====================

Signature::

    * Library: urlmon
    * Return value: HRESULT

Parameters::

    ** DWORD dwOption option
    *  LPSTR pcszUAOut
    *  DWORD *cbSize

Ensure::

    cbSize

Middle::

    uint32_t length = ret == S_OK ? copy_uint32(cbSize) : 0;

Logging::

    S user_agent length, pcszUAOut


GetBestInterfaceEx
==================

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  struct sockaddr *pDestAddr
    *  PDWORD pdwBestIfIndex


WNetGetProviderNameW
====================

Signature::

    * Is success: ret == NO_ERROR
    * Library: mpr
    * Return value: DWORD

Parameters::

    *  DWORD dwNetType
    *  LPTSTR lpProviderName
    *  LPDWORD lpBufferSize

Ensure::

    lpBufferSize

Logging::

    x net_type dwNetType
