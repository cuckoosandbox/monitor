Signature::

    * Calling convention: WINAPI
    * Category: file
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateFile
============

Signature::

    * Mode: exploit

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
    status_info IoStatusBlock->Information NtCreateFile_IoStatusBlock_Information

Ensure::

    FileHandle
    IoStatusBlock

Pre::

    // Not sure what other value we could be handing out here (in any case
    // this value should always be overwritten by the kernel anyway).
    IoStatusBlock->Information = 0xffffffff;
    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

Middle::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    logging_file_trigger(filepath);

Logging::

    i share_access share_access
    u filepath filepath
    u filepath_r filepath_r
    l status_info IoStatusBlock->Information

Post::

    if(NT_SUCCESS(ret) != FALSE && hook_in_monitor() != 0) {
        ignored_object_add(*FileHandle);
    }

    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);


NtDeleteFile
============

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    pipe("FILE_DEL:%Z", filepath);

    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

Interesting::

    u filepath

Logging::

    u filepath filepath
    u filepath_r filepath_r

Post::

    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);


NtOpenFile
==========

Signature::

    * Mode: exploit

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
    status_info IoStatusBlock->Information NtCreateFile_IoStatusBlock_Information

Ensure::

    FileHandle
    IoStatusBlock

Pre::

    // Not sure what other value we could be handing out here (in any case
    // this value should always be overwritten by the kernel anyway).
    IoStatusBlock->Information = 0xffffffff;
    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

Middle::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    logging_file_trigger(filepath);

Logging::

    i share_access share_access
    u filepath filepath
    u filepath_r filepath_r
    l status_info IoStatusBlock->Information

Post::

    if(NT_SUCCESS(ret) != FALSE && hook_in_monitor() != 0) {
        ignored_object_add(*FileHandle);
    }

    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);


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

    b buffer IoStatusBlock->Information, Buffer


NtWriteFile
===========

Signature::

    * Mode: exploit

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

Interesting::

    h file_handle

Middle::

    wchar_t *filepath = NULL;
    if(is_std_handle(FileHandle) == 0) {
        filepath = get_unicode_buffer();
        path_get_full_path_handle(FileHandle, filepath);
    }

Logging::

    b buffer (uintptr_t) Length, Buffer
    u filepath filepath

Post::

    if(NT_SUCCESS(ret) != FALSE && filepath != NULL) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


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

Interesting::

    h file_handle

Prelog::

    b input_buffer (uintptr_t) InputBufferLength, InputBuffer

Logging::

    b output_buffer (uintptr_t) copy_uint32(&IoStatusBlock->Information), OutputBuffer


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

    u dirpath dirpath

Post::

    free_unicode_buffer(dirpath);


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

    BOOLEAN value = FALSE;
    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            copy_bytes(&value, FileInformation, sizeof(BOOLEAN)) == 0 &&
            value != FALSE) {
        wchar_t *filepath = get_unicode_buffer();
        path_get_full_path_handle(FileHandle, filepath);
        pipe("FILE_DEL:%Z", filepath);
        free_unicode_buffer(filepath);
    }
    if(FileInformation != NULL && Length >= sizeof(FILE_RENAME_INFORMATION) &&
            FileInformationClass == FileRenameInformation) {
        FILE_RENAME_INFORMATION *rename_information =
            (FILE_RENAME_INFORMATION *) FileInformation;
        wchar_t *input = get_unicode_buffer(), *output = get_unicode_buffer();

        path_get_full_path_handle(FileHandle, input);

        OBJECT_ATTRIBUTES objattr; UNICODE_STRING unistr;
        unistr.Length = rename_information->FileNameLength;
        unistr.MaximumLength = rename_information->FileNameLength;
        unistr.Buffer = rename_information->FileName;
        InitializeObjectAttributes(
            &objattr, &unistr, 0, rename_information->RootDirectory, NULL
        );
        path_get_full_path_objattr(&objattr, output);

        pipe("FILE_MOVE:%Z::%Z", input, output);
        free_unicode_buffer(input);
        free_unicode_buffer(output);
    }

Interesting::

    h file_handle


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

    wchar_t *dirpath_r = extract_unicode_string_objattr(ObjectAttributes);

Interesting::

    u dirpath
    i desired_access

Logging::

    u dirpath dirpath
    u dirpath_r dirpath_r

Post::

    free_unicode_buffer(dirpath);
    free_unicode_buffer(dirpath_r);


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

    wchar_t *dirpath_r = extract_unicode_string_objattr(ObjectAttributes);

Interesting::

    u dirpath
    i desired_access

Logging::

    u dirpath dirpath
    u dirpath_r dirpath_r

Post::

    free_unicode_buffer(dirpath);
    free_unicode_buffer(dirpath_r);


NtQueryAttributesFile
=====================

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  void *FileInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

Logging::

    u filepath filepath
    u filepath_r filepath_r

Post::

    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);


NtQueryFullAttributesFile
=========================

Parameters::

    *  POBJECT_ATTRIBUTES ObjectAttributes
    *  void *FileInformation

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);

    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

Logging::

    u filepath filepath
    u filepath_r filepath_r

Post::

    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);
