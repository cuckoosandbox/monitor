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

    COPY_FILE_PATH_W(dirpath, lpPathName);

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

    COPY_FILE_PATH_W(dirpath, lpNewDirectory);

Logging::

    u dirpath dirpath


RemoveDirectoryA
================

Signature::

    * Return value: BOOL

Parameters::

    *  LPCTSTR lpPathName

Pre::

    COPY_FILE_PATH_A(dirpath, lpPathName);

Logging::

    u dirpath dirpath


RemoveDirectoryW
================

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpPathName

Pre::

    COPY_FILE_PATH_W(dirpath, lpPathName);

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

    wchar_t *newfilepath = get_unicode_buffer();
    COPY_FILE_PATH_W(oldfilepath, lpExistingFileName);
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

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

    COPY_FILE_PATH_A(filepath, lpFileName);

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

    COPY_FILE_PATH_W(filepath, lpFileName);

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

    COPY_FILE_PATH_A(oldfilepath, lpExistingFileName);
    COPY_FILE_PATH_A(newfilepath, lpNewFileName);

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

    COPY_FILE_PATH_W(oldfilepath, lpExistingFileName);
    COPY_FILE_PATH_W(newfilepath, lpNewFileName);

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

    COPY_FILE_PATH_W(oldfilepath, lpExistingFileName);
    COPY_FILE_PATH_W(newfilepath, lpNewFileName);

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

    COPY_FILE_PATH_A(filepath, lpFileName);
    pipe("FILE_DEL:%Z", filepath);

Logging::

    u filepath filepath


DeleteFileW
===========

Signature::

    * Return value: BOOL

Parameters::

    *  LPWSTR lpFileName

Pre::

    COPY_FILE_PATH_W(filepath, lpFileName);
    pipe("FILE_DEL:%Z", filepath);

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

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass information_class
    *  LPVOID lpFIleInformation
    *  DWORD dwBufferSize


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

Ensure::

    * lpBytesReturned

Prelog::

    b input_buffer nInBufferSize, lpInBuffer

Logging::

    B output_buffer lpBytesReturned, lpOutBuffer
