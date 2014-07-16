Signature::

    * Calling convention: WINAPI
    * Category: network


URLDownloadToFileW
==================

Signature::

    * Return value: HRESULT

Parameters::

    *  LPUNKNOWN pCaller
    ** LPWSTR szURL
    ** LPWSTR szFileName
    *  DWORD dwReserved
    *  LPVOID lpfnCB

Post::

    if(ret == S_OK) {
        pipe("FILE_NEW:%S", szFileName);
    }


InternetOpenA
=============

Signature::

    * Return value: HINTERNET

Parameters::

    ** LPCTSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPCTSTR lpszProxyName proxy_name
    ** LPCTSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags


InternetOpenW
=============

Signature::

    * Return value: HINTERNET

Parameters::

    ** LPWSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPWSTR lpszProxyName proxy_name
    ** LPWSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags


InternetConnectA
================

Signature::

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


InternetConnectW
================

Signature::

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


InternetOpenUrlA
================

Signature::

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
    if(headers_length == -1) {
        headers_length = strlen(lpszHeaders);
    }

Logging::

    b headers headers_length, lpszHeaders


InternetOpenUrlW
================

Signature::

    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet
    ** LPWSTR lpszUrl
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    ** DWORD dwFlags
    *  DWORD_PTR dwContext

Pre::

    int headers_length = dwHeadersLength;
    if(headers_length == -1) {
        headers_length = lstrlenW(lpszHeaders);
    }

Logging::

    b headers headers_length, lpszHeaders


HttpOpenRequestA
================

Signature::

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


HttpOpenRequestW
================

Signature::

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


HttpSendRequestA
================

Signature::

    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPCTSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    int headers_length = dwHeadersLength;
    if(headers_length == -1) {
        headers_length = strlen(lpszHeaders);
    }

Logging::

    S headers headers_length, lpszHeaders
    b post_data dwOptionalLength, lpOptional


HttpSendRequestW
================

Signature::

    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    int headers_length = dwHeadersLength;
    if(headers_length == -1) {
        headers_length = lstrlenW(lpszHeaders);
    }

Logging::

    U headers headers_length, lpszHeaders
    b post_data dwOptionalLength, lpOptional


InternetReadFile
================

Signature::

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

    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle


DnsQuery_A
==========

Signature::

    * Return value: DNS_STATUS

Parameters::

    ** PCSTR lpstrName hostname
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved


DnsQuery_UTF8
=============

Signature::

    * Return value: DNS_STATUS

Parameters::

    *  LPBYTE lpstrName
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved

Logging::

    s hostname lpstrName


DnsQuery_W
==========

Signature::

    * Return value: DNS_STATUS

Parameters::

    ** PWSTR lpstrName hostname
    ** WORD wType dns_type
    ** DWORD Options options
    *  PVOID pExtra
    *  PDNS_RECORD *ppQueryResultsSet
    *  PVOID *pReserved


getaddrinfo
===========

Signature::

    * Return value: int

Parameters::

    ** PCSTR pNodeName hostname
    ** PCSTR pServiceName service_name
    *  const ADDRINFOA *pHints
    *  PADDRINFOA *ppResult


GetAddrInfoW
============

Signature::

    * Return value: int

Parameters::

    ** PCWSTR pNodeName hostname
    ** PCWSTR pServiceName service_name
    *  const ADDRINFOW *pHints
    *  PADDRINFOW *ppResult
