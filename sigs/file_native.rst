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
