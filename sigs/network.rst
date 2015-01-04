Signature::

    * Calling convention: WINAPI
    * Category: network


URLDownloadToFileW
==================

Signature::

    * Library: urlmon
    * Return value: HRESULT

Parameters::

    *  LPUNKNOWN pCaller
    ** LPWSTR szURL url
    ** LPWSTR szFileName filepath
    *  DWORD dwReserved
    *  LPVOID lpfnCB

Interesting::

    u url
    u filepath

Post::

    if(ret == S_OK) {
        pipe("FILE_NEW:%Z", szFileName);
    }


InternetCrackUrlA
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl url
    *  DWORD dwUrlLength
    ** DWORD dwFlags flags
    *  LPURL_COMPONENTSA lpUrlComponents


InternetCrackUrlW
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl url
    *  DWORD dwUrlLength
    ** DWORD dwFlags flags
    *  LPURL_COMPONENTSW lpUrlComponents


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
        headers_length = strlen(lpszHeaders);
    }

Interesting::

    s url
    S headers_length, lpszHeaders
    i flags

Logging::

    b headers headers_length, lpszHeaders


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
        headers_length = lstrlenW(lpszHeaders);
    }

Interesting::

    u url
    U headers_length, lpszHeaders
    i flags

Logging::

    b headers headers_length, lpszHeaders


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
        headers_length = strlen(lpszHeaders);
    }

Interesting::

    S dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    S headers headers_length, lpszHeaders
    b post_data dwOptionalLength, lpOptional


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
        headers_length = lstrlenW(lpszHeaders);
    }

Interesting::

    U dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    U headers headers_length, lpszHeaders
    b post_data dwOptionalLength, lpOptional


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

Logging::

    B buffer lpdwNumberOfBytesRead, lpBuffer


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

Logging::

    B buffer lpdwNumberOfBytesWritten, lpBuffer


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
