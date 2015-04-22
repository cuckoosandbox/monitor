Signature::

    * Calling convention: WINAPI
    * Category: file
    * Library: kernel32


CreateDirectoryW
================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpPathName
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpPathName, dirpath);

Interesting::

    u dirpath

Logging::

    u dirpath dirpath


CreateDirectoryExW
==================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpTemplateDirectory
    *  LPWSTR lpNewDirectory
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpNewDirectory, dirpath);

Interesting::

    u dirpath

Logging::

    u dirpath dirpath


RemoveDirectoryA
================

Signature::

    * Return value: BOOL

Parameters::

    *  LPCTSTR lpPathName

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathA(lpPathName, dirpath);

Interesting::

    u dirpath

Logging::

    u dirpath dirpath


RemoveDirectoryW
================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpPathName

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpPathName, dirpath);

Interesting::

    u dirpath

Logging::

    u dirpath dirpath


MoveFileWithProgressW
=====================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpExistingFileName
    *  LPWSTR lpNewFileName
    *  LPPROGRESS_ROUTINE lpProgressRoutine
    *  LPVOID lpData
    ** DWORD dwFlags flags

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Interesting::

    u oldfilepath
    u newfilepath

Logging::

    u oldfilepath oldfilepath
    u newfilepath newfilepath

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }


FindFirstFileExA
================

Signature::

    * Return value: HANDLE

Parameters::

    *  LPCTSTR lpFileName
    *  FINDEX_INFO_LEVELS fInfoLevelId
    *  LPVOID lpFindFileData
    *  FINDEX_SEARCH_OPS fSearchOp
    *  LPVOID lpSearchFilter
    *  DWORD dwAdditionalFlags

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathA(lpFileName, filepath);

Logging::

    u filepath filepath


FindFirstFileExW
================

Signature::

    * Return value: HANDLE

Parameters::

    *  LPWSTR lpFileName
    *  FINDEX_INFO_LEVELS fInfoLevelId
    *  LPVOID lpFindFileData
    *  FINDEX_SEARCH_OPS fSearchOp
    *  LPVOID lpSearchFilter
    *  DWORD dwAdditionalFlags

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

Logging::

    u filepath filepath


CopyFileA
=========

Signature::

    * Return value: BOOL

Parameters::

    *  LPCTSTR lpExistingFileName
    *  LPCTSTR lpNewFileName
    ** BOOL bFailIfExists fail_if_exists

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathA(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathA(lpNewFileName, newfilepath);

Interesting::

    u oldfilepath
    u newfilepath

Logging::

    u oldfilepath oldfilepath
    u newfilepath newfilepath


CopyFileW
=========

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpExistingFileName
    *  LPWSTR lpNewFileName
    ** BOOL bFailIfExists fail_if_exists

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathW(lpNewFileName, newfilepath);

Interesting::

    u oldfilepath
    u newfilepath

Logging::

    u oldfilepath oldfilepath
    u newfilepath newfilepath


CopyFileExW
===========

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpExistingFileName
    *  LPWSTR lpNewFileName
    *  LPPROGRESS_ROUTINE lpProgressRoutine
    *  LPVOID lpData
    *  LPBOOL pbCancel
    ** DWORD dwCopyFlags flags

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathW(lpNewFileName, newfilepath);

Interesting::

    u oldfilepath
    u newfilepath

Logging::

    u oldfilepath oldfilepath
    u newfilepath newfilepath


DeleteFileA
===========

Signature::

    * Return value: BOOL

Parameters::

    *  LPCSTR lpFileName

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathA(lpFileName, filepath);
    pipe("FILE_DEL:%Z", filepath);

Interesting::

    u filepath

Logging::

    u filepath filepath


DeleteFileW
===========

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpFileName

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);
    pipe("FILE_DEL:%Z", filepath);

Interesting::

    u filepath

Logging::

    u filepath filepath


GetFileType
===========

Signature::

    * Is success: 1
    * Return value: DWORD

Parameters::

    ** HANDLE hFile file_handle


GetFileSize
===========

Signature::

    * Is success: ret != INVALID_FILE_SIZE && lpFileSizeHigh != NULL
    * Return value: DWORD

Parameters::

    ** HANDLE hFile file_handle
    *  LPDWORD lpFileSizeHigh file_size_high

Logging::

    i file_size_low ret


GetFileSizeEx
=============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** PLARGE_INTEGER lpFileSize file_size


GetFileInformationByHandle
==========================

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    *  LPBY_HANDLE_FILE_INFORMATION lpFIleInformation


GetFileInformationByHandleEx
============================

Signature::

    * Minimum: Windows 7
    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass information_class
    *  LPVOID lpFIleInformation
    *  DWORD dwBufferSize

Flags::

    information_class


DeviceIoControl
===============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hDevice device_handle
    ** DWORD dwIoControlCode control_code
    *  LPVOID lpInBuffer
    *  DWORD nInBufferSize
    *  LPVOID lpOutBuffer
    *  DWORD nOutBufferSize
    *  LPDWORD lpBytesReturned
    *  LPOVERLAPPED lpOverlapped

Flags::

    control_code

Ensure::

    lpBytesReturned

Interesting::

    h device_handle

Prelog::

    b input_buffer nInBufferSize, lpInBuffer

Logging::

    B output_buffer lpBytesReturned, lpOutBuffer


GetSystemDirectoryA
===================

Signature::

    * Is success: ret > 0
    * Return value: UINT

Parameters::

    *  LPTSTR lpBuffer
    *  UINT uSize

Logging::

    S dirpath ret, lpBuffer


GetSystemDirectoryW
===================

Signature::

    * Is success: ret > 0
    * Return value: UINT

Parameters::

    *  LPWSTR lpBuffer
    *  UINT uSize

Logging::

    U dirpath ret, lpBuffer


GetSystemWindowsDirectoryA
==========================

Signature::

    * Is success: ret > 0
    * Return value: UINT

Parameters::

    *  LPTSTR lpBuffer
    *  UINT uSize

Logging::

    S dirpath ret, lpBuffer


GetSystemWindowsDirectoryW
==========================

Signature::

    * Is success: ret > 0
    * Return value: UINT

Parameters::

    *  LPWSTR lpBuffer
    *  UINT uSize

Logging::

    U dirpath ret, lpBuffer


SetFileAttributesW
==================

Signature::

    * Return value: BOOL

Parameters::

    *  LPCWSTR lpFileName
    ** DWORD dwFileAttributes file_attributes

Flags::

    file_attributes

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

Logging::

    u filepath filepath


GetFileAttributesW
==================

Signature::

    * Is success: ret != INVALID_FILE_ATTRIBUTES
    * Return value: DWORD

Parameters::

    *  LPCWSTR lpFileName

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

Logging::

    u filepath filepath
    d file_attributes ret
