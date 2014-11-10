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

    COPY_UNICODE_STRING(class, Class);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

Logging::

    u regkey regkey
    O class &class


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

Logging::

    u regkey regkey


NtOpenKeyEx
===========

Signature::

    * Minimum: Windows 7

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

Logging::

    u regkey regkey


NtRenameKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING NewName

Pre::

    COPY_UNICODE_STRING(new_name, NewName);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    O new_name &new_name
    u regkey regkey


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

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    B buffer ResultLength, KeyInformation
    u regkey regkey


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

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

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
    R value &reg_type, &data_length, data


NtSetValueKey
=============

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName
    ** ULONG TitleIndex index
    ** ULONG Type reg_type
    *  PVOID Data
    *  ULONG DataSize

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Logging::

    R value &Type, &DataSize, Data
    u regkey regkey


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

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

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
    R value &reg_type, &data_length, data


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

    B buffer BufferLength, ValueBuffer
    u regkey regkey


NtDeleteKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    u regkey regkey


NtDeleteValueKey
================

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Logging::

    u regkey regkey


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

Logging::

    u filepath source_file
    u regkey regkey


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

Logging::

    u filepath source_file
    u regkey regkey


NtLoadKeyEx
===========

Signature::

    * Minimum: Windows 7

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

Logging::

    u filepath source_file
    u regkey regkey


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

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    B buffer ResultLength, KeyInformation
    u regkey regkey


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

Logging::

    u regkey regkey
    u filepath filepath


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

Logging::

    u regkey regkey
    u filepath filepath
