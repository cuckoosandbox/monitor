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
    u dirpath_r lpPathName

Post::

    free_unicode_buffer(dirpath);


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
    u dirpath_r lpNewDirectory

Post::

    free_unicode_buffer(dirpath);


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
    s dirpath_r lpPathName

Post::

    free_unicode_buffer(dirpath);


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
    u dirpath_r lpPathName

Post::

    free_unicode_buffer(dirpath);


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
    u oldfilepath_r lpExistingFileName
    u newfilepath newfilepath
    u newfilepath_r lpNewFileName

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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
    s filepath_r lpFileName

Post::

    free_unicode_buffer(filepath);


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
    u filepath_r lpFileName

Post::

    free_unicode_buffer(filepath);


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
    s oldfilepath_r lpExistingFileName
    u newfilepath newfilepath
    s newfilepath_r lpNewFileName

Post::

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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
    u oldfilepath_r lpExistingFileName
    u newfilepath newfilepath
    u newfilepath_r lpNewFileName

Post::

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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
    u oldfilepath_r lpExistingFileName
    u newfilepath newfilepath
    u newfilepath_r lpNewFileName

Post::

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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
    u filepath_r lpFileName

Post::

    free_unicode_buffer(filepath);


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

    * Prune: resolve
    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass information_class
    *  LPVOID lpFIleInformation
    *  DWORD dwBufferSize

Flags::

    information_class


SetFilePointer
==============

Signature::

    * Is success: ret != INVALID_SET_FILE_POINTER
    * Return value: DWORD

Parameters::

    ** HANDLE hFile file_handle
    *  LONG lDistanceToMove
    *  PLONG lpDistanceToMoveHigh
    ** DWORD dwMoveMethod move_method

Pre::

    uint64_t offset = lDistanceToMove;
    if(lpDistanceToMoveHigh != NULL) {
        offset += (uint64_t) copy_uint32(lpDistanceToMoveHigh) << 32;
    }

Logging::

    q offset offset


SetFilePointerEx
================

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    *  LARGE_INTEGER liDistanceToMove
    ** PLARGE_INTEGER lpNewFilePointer offset
    ** DWORD dwMoveMethod move_method


SetFileInformationByHandle
==========================

Signature::

    * Prune: resolve
    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass information_class
    *  LPVOID lpFileInformation
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

Flags::

    control_code

Ensure::

    lpBytesReturned

Interesting::

    h device_handle

Prelog::

    b input_buffer nInBufferSize, lpInBuffer

Logging::

    b output_buffer (uintptr_t) copy_uint32(lpBytesReturned), lpOutBuffer


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


GetTempPathW
============

Signature::

    * Is success: ret != 0
    * Return value: DWORD

Parameters::

    *  DWORD nBufferLength
    *  LPWSTR lpBuffer

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
    u filepath_r lpFileName

Post::

    free_unicode_buffer(filepath);


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
    u filepath_r lpFileName
    i file_attributes ret

Post::

    free_unicode_buffer(filepath);


GetFileAttributesExW
====================

Signature::

    * Return value: BOOL

Parameters::

    *  LPCWSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId info_level
    *  LPVOID lpFileInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

Logging::

    u filepath filepath
    u filepath_r lpFileName

Post::

    free_unicode_buffer(filepath);


SetEndOfFile
============

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle


GetVolumeNameForVolumeMountPointW
=================================

Signature::

    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeMountPoint volume_mount_point
    ** LPWSTR lpszVolumeName volume_name
    *  DWORD cchBufferLength


GetVolumePathNamesForVolumeNameW
================================

Signature::

    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeName volume_name
    ** LPWSTR lpszVolumePathNames volume_path_name
    *  DWORD cchBufferLength
    *  PDWORD lpcchReturnLength


GetVolumePathNameW
==================

Signature::

    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszFileName filepath
    ** LPWSTR lpszVolumePathName volume_path_name
    *  DWORD cchBufferLength


GetShortPathNameW
=================

Signature::

    * Is success: ret != 0
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszLongPath filepath
    ** LPWSTR lpszShortPath shortpath
    *  DWORD cchBuffer


SearchPathW
===========

Signature::

    * Is success: ret != 0
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpPath searchpath
    ** LPCWSTR lpFileName filename
    ** LPCWSTR lpExtension extension
    *  DWORD nBufferLength
    *  LPWSTR lpBuffer
    *  LPWSTR *lpFilePart

Logging::

    u filepath lpBuffer


SetFileTime
===========

Signature::

    * Return value: BOOL

Parameters::

    ** HANDLE hFile file_handle
    *  FILETIME *lpCreationTime
    *  FILETIME *lpLastAccessTime
    *  FILETIME *lpLastWriteTime
