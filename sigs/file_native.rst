Signature::

    * Calling convention: WINAPI
    * Category: file
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateFile
============

Signature::

    * Special: true

Parameters::

    ** PHANDLE FileHandle file_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PLARGE_INTEGER AllocationSize
    ** ULONG FileAttributes file_attributes
    *  ULONG ShareAccess share_access
    ** ULONG CreateDisposition create_disposition
    ** ULONG CreateOptions create_options
    *  PVOID EaBuffer
    *  ULONG EaLength

Flags::

    desired_access
    file_attributes
    share_access
    create_disposition
    create_options

Pre::

    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

Middle::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Logging::

    i share_access share_access
    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        if(hook_in_monitor() != 0) {
            ignored_object_add(*FileHandle);
        }
        else {
            dropped_add(*FileHandle, filepath);
        }
    }


NtDeleteFile
============

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

    COPY_OBJECT_ATTRIBUTES(objattr, ObjectAttributes);
    pipe("FILE_DEL:%Z", filepath);

Interesting::

    u filepath

Replace::

    ObjectAttributes &objattr

Logging::

    u filepath filepath


NtOpenFile
==========

Signature::

    * Special: true

Parameters::

    ** PHANDLE FileHandle file_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  ULONG ShareAccess share_access
    ** ULONG OpenOptions open_options

Flags::

    desired_access
    share_access
    open_options

Pre::

    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

Middle::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Logging::

    i share_access share_access
    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        if(hook_in_monitor() != 0) {
            ignored_object_add(*FileHandle);
        }
        else {
            dropped_add(*FileHandle, filepath);
        }
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

Ensure::

    IoStatusBlock

Pre::

    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

Interesting::

    h file_handle

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

Interesting::

    h file_handle

Post::

    if(NT_SUCCESS(ret) != FALSE) {
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

Flags::

    control_code

Ensure::

    IoStatusBlock

Pre::

    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

Interesting::

    h file_handle

Prelog::

    b input_buffer InputBufferLength, InputBuffer

Logging::

    b output_buffer IoStatusBlock->Information, OutputBuffer


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
    ** FILE_INFORMATION_CLASS FileInformationClass information_class
    *  BOOLEAN ReturnSingleEntry
    *  PUNICODE_STRING FileName
    *  BOOLEAN RestartScan

Flags::

    information_class

Ensure::

    IoStatusBlock

Pre::

    wchar_t *dirpath = get_unicode_buffer();

    OBJECT_ATTRIBUTES objattr;
    InitializeObjectAttributes(&objattr, FileName, 0, FileHandle, NULL);
    path_get_full_path_objattr(&objattr, dirpath);

    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

Interesting::

    h file_handle

Logging::

    b file_information IoStatusBlock->Information, FileInformation
    u dirpath dirpath


NtQueryInformationFile
======================

Parameters::

    ** HANDLE FileHandle file_handle
    *  PIO_STATUS_BLOCK IoStatusBlock
    *  PVOID FileInformation
    *  ULONG Length
    ** FILE_INFORMATION_CLASS FileInformationClass information_class

Flags::

    information_class

Ensure::

    IoStatusBlock

Pre::

    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

Interesting::

    h file_handle

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

Flags::

    information_class

Pre::

    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            *(BOOLEAN *) FileInformation != FALSE) {
        wchar_t *filepath = get_unicode_buffer();
        path_get_full_path_handle(FileHandle, filepath);
        pipe("FILE_DEL:%Z", filepath);
    }

Interesting::

    h file_handle

Logging::

     b file_information Length, FileInformation


NtOpenDirectoryObject
=====================

Parameters::

    ** PHANDLE DirectoryHandle directory_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Flags::

    desired_access

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, dirpath);

Interesting::

    u dirpath
    i desired_access

Logging::

    u dirpath dirpath


NtCreateDirectoryObject
=======================

Parameters::

    ** PHANDLE DirectoryHandle directory_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Flags::

    desired_access

Pre::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, dirpath);

Interesting::

    u dirpath
    i desired_access

Logging::

    u dirpath dirpath


NtQueryAttributesFile
=====================

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  void *FileInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Logging::

    u filepath filepath


NtQueryFullAttributesFile
=========================

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  void *FileInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

Logging::

    u filepath filepath
