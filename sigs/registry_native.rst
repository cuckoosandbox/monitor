Signature::

    * Calling convention: WINAPI
    * Category: registry
    * Library: ntdll
    * Return value: NTSTATUS


NtCreateKey
===========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG TitleIndex index
    *  PUNICODE_STRING Class
    ** ULONG CreateOptions options
    *  PULONG Disposition

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
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

Logging::

    u regkey regkey


NtOpenKeyEx
===========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG OpenOptions options

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

    COPY_FILE_PATH_OA(newfilepath, NewHiveFileName);
    COPY_FILE_PATH_OA(backupfilepath, BackupHiveFileName);

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
    ** KEY_INFORMATION_CLASS KeyInformationClass class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

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
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

Logging::

    B buffer ResultLength, KeyValueInformation
    u regkey regkey


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

    b buffer DataSize, Data
    u regkey regkey


NtQueryValueKey
===============

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING ValueName
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Ensure::

    ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

Logging::

    B buffer ResultLength, KeyValueInformation
    u regkey regkey


NtQueryMultipleValueKey
=======================

Parameters::

    ** HANDLE KeyHandle
    *  PKEY_VALUE_ENTRY ValueEntries
    ** ULONG EntryCount
    *  PVOID ValueBuffer
    *  PULONG BufferLength
    *  PULONG RequiredBufferLength

Logging::

    B buffer RequiredBufferLength, ValueBuffer


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

    COPY_FILE_PATH_OA(source_file, SourceFile);

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

    COPY_FILE_PATH_OA(source_file, SourceFile);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

Logging::

    u filepath source_file
    u regkey regkey


NtLoadKeyEx
===========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key

Pre::

    COPY_FILE_PATH_OA(source_file, SourceFile);

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

Logging::

    u filepath source_file
    u regkey regkey


NtQueryKey
==========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** KEY_INFORMATION_CLASS KeyInformationClass class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(KeyHandle, regkey);

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
    reg_get_key_objattr(KeyHandle, regkey);

Logging::

    u regkey regkey


NtSaveKeyEx
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** HANDLE FileHandle file_handle
    ** ULONG Format format

Pre::

    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(KeyHandle, regkey);

Logging::

    u regkey regkey
