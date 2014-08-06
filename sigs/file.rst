Signature::

    * Calling convention: WINAPI
    * Category: file
    * Library: kernel32


CreateDirectoryW
================

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpPathName dirpath
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryExW
==================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpTemplateDirectory
    ** LPWSTR lpNewDirectory dirpath
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes


RemoveDirectoryA
================

Signature::

    * Return value: BOOL

Parameters::

    ** LPCTSTR lpPathName dirpath


RemoveDirectoryW
================

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpPathName dirpath


MoveFileWithProgressW
=====================

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpExistingFileName oldfilepath
    ** LPWSTR lpNewFileName newfilepath
    *  LPPROGRESS_ROUTINE lpProgressRoutine
    *  LPVOID lpData
    *  DWORD dwFlags

Post::

    if(ret != FALSE) {
        pipe("FILE_MOVE:%Z::%Z", lpExistingFileName, lpNewFileName);
    }


FindFirstFileExA
================

Signature::

    * Return value: HANDLE

Parameters::

    ** LPCTSTR lpFileName filepath
    *  FINDEX_INFO_LEVELS fInfoLevelId
    *  LPVOID lpFindFileData
    *  FINDEX_SEARCH_OPS fSearchOp
    *  LPVOID lpSearchFilter
    *  DWORD dwAdditionalFlags


FindFirstFileExW
================

Signature::

    * Return value: HANDLE

Parameters::

    ** LPWSTR lpFileName filepath
    *  FINDEX_INFO_LEVELS fInfoLevelId
    *  LPVOID lpFindFileData
    *  FINDEX_SEARCH_OPS fSearchOp
    *  LPVOID lpSearchFilter
    *  DWORD dwAdditionalFlags


CopyFileA
=========

Signature::

    * Return value: BOOL

Parameters::

    ** LPCTSTR lpExistingFileName oldfilepath
    ** LPCTSTR lpNewFileName newfilepath
    *  BOOL bFailIfExists


CopyFileW
=========

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpExistingFileName oldfilepath
    ** LPWSTR lpNewFileName newfilepath
    *  BOOL bFailIfExists


CopyFileExW
===========

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpExistingFileName oldfilepath
    ** LPWSTR lpNewFileName newfilepath
    *  LPPROGRESS_ROUTINE lpProgressRoutine
    *  LPVOID lpData
    *  LPBOOL pbCancel
    *  DWORD dwCopyFlags


DeleteFileA
===========

Signature::

    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName filepath

Pre::

    wchar_t path[MAX_PATH];

    // copy ascii to unicode string
    for (int i = 0; lpFileName[i] != 0 && i < MAX_PATH; i++) {
        path[i] = lpFileName[i];
    }

    ensure_absolute_path(path, path, strlen(lpFileName));

    pipe("FILE_DEL:%Z", path);


DeleteFileW
===========

Signature::

    * Return value: BOOL

Parameters::

    ** LPWSTR lpFileName filepath

Pre::

    wchar_t path[MAX_PATH];

    ensure_absolute_path(path, lpFileName, lstrlenW(lpFileName));

    pipe("FILE_DEL:%Z", path);


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

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass information_class
    *  LPVOID lpFIleInformation
    *  DWORD dwBufferSize
