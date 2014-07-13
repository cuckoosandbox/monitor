NtCreateFile
============

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** PHANDLE FileHandle file_handle
    ** ACCESS_MASK DesiredAccess
    ** POBJECT_ATTRIBUTES ObjectAttributes filepath
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PLARGE_INTEGER AllocationSize
    ** ULONG FileAttributes
    ** ULONG ShareAccess
    ** ULONG CreateDisposition
    ** ULONG CreateOptions
    *  PVOID EaBuffer
    *  ULONG EaLength

Post::

    if(NT_SUCCESS(ret) && (DesiredAccess & DUMP_FILE_MASK) != 0) {
        dump_file_add(*FileHandle, ObjectAttributes);
    }


NtDeleteFile
============

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** POBJECT_ATTRIBUTES ObjectAttributes filepath

Pre::

    pipe("FILE_DEL:%O", ObjectAttributes);


NtOpenFile
==========

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** PHANDLE FileHandle
    ** ACCESS_MASK DesiredAccess
    ** POBJECT_ATTRIBUTES ObjectAttributes filepath
    *  PIO_STATUS_BLOCK IoStatusBlock
    ** ULONG ShareAccess
    ** ULONG OpenOptions

Post::

    if(NT_SUCCESS(ret) && (DesiredAccess & DUMP_FILE_MASK) != 0) {
        dump_file_add(*FileHandle, ObjectAttributes);
    }


NtReadFile
==========

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID Buffer
    ** ULONG Length
    ** PLARGE_INTEGER ByteOffset
    *  PULONG Key

Logging::

    * b buffer IoStatusBlock->Information, Buffer


NtWriteFile
===========

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID Buffer
    *  ULONG Length
    ** PLARGE_INTEGER ByteOffset
    *  PULONG Key

Logging::

    b buffer Length, Buffer

Post::

    if(NT_SUCCESS(ret)) {
        dump_file_wrote(FileHandle);
    }


NtDeviceIoControlFile
=====================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    ** ULONG IoControlCode
    *  PVOID InputBuffer
    *  ULONG InputBufferLength
    *  PVOID OutputBuffer
    *  ULONG OutputBufferLength

Pre::

    void *mem_copy = malloc(InputBufferLength);
    if(mem_copy != NULL) {
        memcpy(mem_copy, InputBuffer, InputBufferLength);
    }

Logging::

    b input_buffer InputBufferLength, mem_copy
    b output_buffer IoStatusBlock->Information, OutputBuffer

Post::

    free(mem_copy);


NtQueryDirectoryFile
====================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    *  FILE_INFORMATION_CLASS FileInformationClass
    *  BOOLEAN ReturnSingleEntry
    ** PUNICODE_STRING FileName dirpath
    *  BOOLEAN RestartScan

Logging::

    b file_information IoStatusBlock->Information, FileInformation


NtQueryInformationFile
======================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    ** FILE_INFORMATION_CLASS FileInformationClass

Logging::

    b file_information IoStatusBlock->Information, FileInformation


NtSetInformationFile
====================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** HANDLE FileHandle
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    ** FILE_INFORMATION_CLASS FileInformationClass

Pre::

    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            *(BOOLEAN *) FileInformation != FALSE) {

        wchar_t path[MAX_PATH];
        path_from_handle(FileHandle, path, MAX_PATH);
        pipe("FILE_DEL:%Z", path);
    }

Logging::

     b file_information IoStatusBlock->Information, FileInformation


NtOpenDirectoryObject
=====================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** PHANDLE DirectoryHandle
    ** ACCESS_MASK DesiredAccess
    ** POBJECT_ATTRIBUTES ObjectAttributes dirpath


NtCreateDirectoryObject
=======================

Signature::

    * Return value: NTSTATUS
    * Calling convention: WINAPI

Parameters::

    ** PHANDLE DirectoryHandle
    ** ACCESS_MASK DesiredAccess
    ** POBJECT_ATTRIBUTES ObjectAttributes dirpath


CreateDirectoryW
================

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

Parameters::

    ** LPWSTR lpPathName dirpath
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryExW
==================

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

Parameters::

    *  LPWSTR lpTemplateDirectory
    ** LPWSTR lpNewDirectory dirpath
    *  LPSECURITY_ATTRIBUTES lpSecurityAttributes


RemoveDirectoryA
================

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

Parameters::

    ** LPCTSTR lpPathName dirpath


RemoveDirectoryW
================

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

Parameters::

    ** LPWSTR lpPathName dirpath


MoveFileWithProgressW
=====================

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

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
    * Calling convention: WINAPI

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
    * Calling convention: WINAPI

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
    * Calling convention: WINAPI

Parameters::

    ** LPCTSTR lpExistingFileName oldfilepath
    ** LPCTSTR lpNewFileName newfilepath
    *  BOOL bFailIfExists


CopyFileW
=========

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

Parameters::

    ** LPWSTR lpExistingFileName oldfilepath
    ** LPWSTR lpNewFileName newfilepath
    *  BOOL bFailIfExists


CopyFileExW
===========

Signature::

    * Return value: BOOL
    * Calling convention: WINAPI

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
    * Calling convention: WINAPI

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
    * Calling convention: WINAPI

Parameters::

    ** LPWSTR lpFileName filepath

Pre::

    wchar_t path[MAX_PATH];

    ensure_absolute_path(path, lpFileName, lstrlenW(lpFileName));

    pipe("FILE_DEL:%Z", path);
