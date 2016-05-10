Signature::

    * Calling convention: WINAPI
    * Category: registry
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateKey
===========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG TitleIndex index
    *  PUNICODE_STRING Class
    ** ULONG CreateOptions options
    ** PULONG Disposition disposition

Flags::

    desired_access

Pre::

    wchar_t *class = extract_unicode_string_unistr(Class);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

Interesting::

    u regkey
    i desired_access
    i index
    i options
    i disposition

Logging::

    u regkey regkey
    u class class

Post::

    free_unicode_buffer(class);
    free_unicode_buffer(regkey);


NtOpenKey
=========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Flags::

    desired_access

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

Interesting::

    u regkey
    i desired_access

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtOpenKeyEx
===========

Signature::

    * Prune: resolve

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess desired_access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG OpenOptions options

Flags::

    desired_access

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

Interesting::

    u regkey
    i desired_access

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtRenameKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING NewName

Pre::

    wchar_t *new_name = extract_unicode_string_unistr(NewName);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    u new_name new_name
    u regkey regkey

Post::

    free_unicode_buffer(new_name);
    free_unicode_buffer(regkey);


NtReplaceKey
============

Parameters::

    *  POBJECT_ATTRIBUTES NewHiveFileName
    ** HANDLE KeyHandle key_handle
    *  POBJECT_ATTRIBUTES BackupHiveFileName

Pre::

    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_path_objattr(NewHiveFileName, newfilepath);

    wchar_t *backupfilepath = get_unicode_buffer();
    path_get_full_path_objattr(BackupHiveFileName, backupfilepath);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    u newfilepath newfilepath
    u backupfilepath backupfilepath
    u regkey regkey

Post::

    free_unicode_buffer(newfilepath);
    free_unicode_buffer(backupfilepath);
    free_unicode_buffer(regkey);


NtEnumerateKey
==============

Parameters::

    ** HANDLE KeyHandle key_handle
    ** ULONG Index index
    ** KEY_INFORMATION_CLASS KeyInformationClass information_class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

Flags::

    information_class

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Interesting::

    u regkey
    i index

Logging::

    b buffer (uintptr_t) *ResultLength, KeyInformation
    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtEnumerateValueKey
===================

Parameters::

    ** HANDLE KeyHandle key_handle
    ** ULONG Index index
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass information_class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Flags::

    information_class
    reg_type reg_type

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Interesting::

    u regkey
    i index

Middle::

    wchar_t *key_name = NULL; uint8_t *data = NULL;
    uint32_t reg_type = REG_NONE, data_length = 0;

    if(NT_SUCCESS(ret) != FALSE) {
        reg_get_info_from_keyvalue(KeyValueInformation, *ResultLength,
            KeyValueInformationClass, &key_name, &reg_type,
            &data_length, &data
        );
    }

Logging::

    u regkey regkey
    u key_name key_name
    i reg_type reg_type
    R value &reg_type, &data_length, data

Post::

    free_unicode_buffer(regkey);
    free_unicode_buffer(key_name);


NtSetValueKey
=============

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName
    ** ULONG TitleIndex index
    ** ULONG Type reg_type
    *  PVOID Data
    *  ULONG DataSize

Flags::

    reg_type reg_type

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Interesting::

    u regkey
    i index
    i reg_type
    b DataSize, Data

Logging::

    i reg_type Type
    R value &Type, &DataSize, Data
    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtQueryValueKey
===============

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass information_class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Flags::

    information_class
    reg_type reg_type

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Interesting::

    u regkey
    i information_class

Middle::

    wchar_t *key_name = NULL; uint8_t *data = NULL;
    uint32_t reg_type = REG_NONE, data_length = 0;

    if(NT_SUCCESS(ret) != FALSE) {
        reg_get_info_from_keyvalue(KeyValueInformation, *ResultLength,
            KeyValueInformationClass, &key_name, &reg_type,
            &data_length, &data
        );
    }

Logging::

    u regkey regkey
    u key_name key_name
    i reg_type reg_type
    R value &reg_type, &data_length, data

Post::

    free_unicode_buffer(regkey);
    free_unicode_buffer(key_name);


NtQueryMultipleValueKey
=======================

Parameters::

    ** HANDLE KeyHandle
    *  PKEY_VALUE_ENTRY ValueEntries
    ** ULONG EntryCount
    *  PVOID ValueBuffer
    *  PULONG BufferLength
    *  PULONG RequiredBufferLength

Ensure::

    BufferLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    b buffer (uintptr_t) *BufferLength, ValueBuffer
    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtDeleteKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtDeleteValueKey
================

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Interesting::

    u regkey

Logging::

    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtLoadKey
=========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile

Pre::

    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

Interesting::

    u regkey
    u source_file

Logging::

    u filepath source_file
    u regkey regkey

Post::

    free_unicode_buffer(source_file);
    free_unicode_buffer(regkey);


NtLoadKey2
==========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags

Pre::

    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

Interesting::

    u regkey
    u source_file
    i flags

Logging::

    u filepath source_file
    u regkey regkey

Post::

    free_unicode_buffer(regkey);
    free_unicode_buffer(source_file);


NtLoadKeyEx
===========

Signature::

    * Prune: resolve

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key

Pre::

    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

Interesting::

    u regkey
    u source_file
    i flags

Logging::

    u filepath source_file
    u regkey regkey

Post::

    free_unicode_buffer(regkey);
    free_unicode_buffer(source_file);


NtQueryKey
==========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** KEY_INFORMATION_CLASS KeyInformationClass information_class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

Flags::

    information_class

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Interesting::

    u regkey
    i information_class

Logging::

    b buffer (uintptr_t) *ResultLength, KeyInformation
    u regkey regkey

Post::

    free_unicode_buffer(regkey);


NtSaveKey
=========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** HANDLE FileHandle file_handle

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_handle(FileHandle, filepath);

Interesting::

    u regkey
    u filepath

Logging::

    u regkey regkey
    u filepath filepath

Post::

    free_unicode_buffer(filepath);
    free_unicode_buffer(regkey);


NtSaveKeyEx
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** HANDLE FileHandle file_handle
    ** ULONG Format format

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_handle(FileHandle, filepath);

Interesting::

    u regkey
    u filepath

Logging::

    u regkey regkey
    u filepath filepath

Post::

    free_unicode_buffer(filepath);
    free_unicode_buffer(regkey);
