Signature::

    * Calling convention: WINAPI
    * Category: file
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateFile
============

Parameters::

    ** PHANDLE FileHandle file_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PLARGE_INTEGER AllocationSize
    ** ULONG FileAttributes file_attributes
    ** ULONG ShareAccess share_access
    ** ULONG CreateDisposition create_disposition
    ** ULONG CreateOptions create_options
    *  PVOID EaBuffer
    *  ULONG EaLength

Middle::

    COPY_FILE_PATH_OA(filepath, ObjectAttributes);

Logging::

    u filepath filepath

Post::

    if(NT_SUCCESS(ret) && (DesiredAccess & DUMP_FILE_MASK) != 0) {
        dropped_add(*FileHandle, ObjectAttributes, filepath);
    }


NtDeleteFile
============

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    COPY_FILE_PATH_OA(filepath, ObjectAttributes);
    pipe("FILE_DEL:%Z", filepath);

Logging::

    u filepath filepath


NtOpenFile
==========

Parameters::

    ** PHANDLE FileHandle file_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PIO_STATUS_BLOCK IoStatusBlock
    ** ULONG ShareAccess share_access
    ** ULONG OpenOptions open_options

Middle::

    COPY_FILE_PATH_OA(filepath, ObjectAttributes);

Logging::

    u filepath filepath

Post::

    if(NT_SUCCESS(ret) && (DesiredAccess & DUMP_FILE_MASK) != 0) {
        dropped_add(*FileHandle, ObjectAttributes, filepath);
    }


NtReadFile
==========

Parameters::

    ** HANDLE FileHandle file_handle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID Buffer
    ** ULONG Length length
    ** PLARGE_INTEGER ByteOffset offset
    *  PULONG Key

Logging::

    * b buffer IoStatusBlock->Information, Buffer


NtWriteFile
===========

Parameters::

    ** HANDLE FileHandle file_handle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID Buffer
    *  ULONG Length
    ** PLARGE_INTEGER ByteOffset offset
    *  PULONG Key

Logging::

    b buffer Length, Buffer

Post::

    if(NT_SUCCESS(ret)) {
        dropped_wrote(FileHandle);
    }


NtDeviceIoControlFile
=====================

Parameters::

    ** HANDLE FileHandle file_handle
    *  HANDLE Event
    *  PIO_APC_ROUTINE ApcRoutine
    *  PVOID ApcContext
    *  PIO_STATUS_BLOCK IoStatusBlock
    ** ULONG IoControlCode control_code
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

Parameters::

    ** HANDLE FileHandle file_handle
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

Parameters::

    ** HANDLE FileHandle file_handle
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    ** FILE_INFORMATION_CLASS FileInformationClass information_class

Logging::

    b file_information IoStatusBlock->Information, FileInformation


NtSetInformationFile
====================

Parameters::

    ** HANDLE FileHandle file_handle
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    ** FILE_INFORMATION_CLASS FileInformationClass information_class

Pre::

    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            *(BOOLEAN *) FileInformation != FALSE) {
        wchar_t *filepath = get_unicode_buffer();
        path_from_handle(FileHandle, filepath);
        pipe("FILE_DEL:%Z", filepath);
    }

Logging::

     b file_information Length, FileInformation


NtOpenDirectoryObject
=====================

Parameters::

    ** PHANDLE DirectoryHandle directory_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    COPY_FILE_PATH_OA(dirpath, ObjectAttributes);

Logging::

    u dirpath dirpath


NtCreateDirectoryObject
=======================

Parameters::

    ** PHANDLE DirectoryHandle directory_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    COPY_FILE_PATH_OA(dirpath, ObjectAttributes);

Logging::

    u dirpath dirpath
