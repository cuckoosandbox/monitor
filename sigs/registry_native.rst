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

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);
    COPY_UNICODE_STRING(sub_key, unistr);
    COPY_UNICODE_STRING(class, Class);

Logging::

    O sub_key &sub_key
    O class &class


NtOpenKey
=========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);
    COPY_UNICODE_STRING(sub_key, unistr);

Logging::

    O sub_key &sub_key


NtOpenKeyEx
===========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG OpenOptions options

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);
    COPY_UNICODE_STRING(sub_key, unistr);

Logging::

    O sub_key &sub_key


NtRenameKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    *  PUNICODE_STRING NewName

Pre::

    COPY_UNICODE_STRING(new_name, NewName);

Logging::

    O new_name &new_name


NtReplaceKey
============

Parameters::

    *  POBJECT_ATTRIBUTES NewHiveFileName
    ** HANDLE KeyHandle
    *  POBJECT_ATTRIBUTES BackupHiveFileName

Pre::

    COPY_OBJECT_ATTRIBUTES(newfilepath, NewHiveFileName);
    COPY_OBJECT_ATTRIBUTES(backupfilepath, BackupHiveFileName);

Logging::

    x newfilepath &newfilepath
    x backupfilepath &backupfilepath


NtEnumerateKey
==============

Parameters::

    ** HANDLE KeyHandle key_handle
    ** ULONG Index index
    ** KEY_INFORMATION_CLASS KeyInformationClass class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

Logging::

    B buffer ResultLength, KeyInformation


NtEnumerateValueKey
===================

Parameters::

    ** HANDLE KeyHandle key_handle
    ** ULONG Index index
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Logging::

    B buffer ResultLength, KeyValueInformation


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

    COPY_UNICODE_STRING(value_name, ValueName);

Logging::

    b buffer DataSize, Data
    O value_name &value_name


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

    COPY_UNICODE_STRING(value_name, ValueName);

Logging::

    B buffer ResultLength, KeyValueInformation
    O value_name &value_name


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


NtDeleteValueKey
================

Parameters::

    ** HANDLE KeyHandle key_handle
    * PUNICODE_STRING ValueName

Pre::

    COPY_UNICODE_STRING(value_name, ValueName);

Logging::

    O value_name &value_name


NtLoadKey
=========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(TargetKey);
    COPY_UNICODE_STRING(target_key, unistr);
    COPY_OBJECT_ATTRIBUTES(source_file, SourceFile);

Logging::

    x filepath &source_file
    O target_key &target_key


NtLoadKey2
==========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(TargetKey);
    COPY_UNICODE_STRING(target_key, unistr);
    COPY_OBJECT_ATTRIBUTES(source_file, SourceFile);

Logging::

    x filepath &source_file
    O target_key &target_key


NtLoadKeyEx
===========

Parameters::

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(TargetKey);
    COPY_UNICODE_STRING(target_key, unistr);
    COPY_OBJECT_ATTRIBUTES(source_file, SourceFile);

Logging::

    x filepath &source_file
    O target_key &target_key



NtQueryKey
==========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** KEY_INFORMATION_CLASS KeyInformationClass class
    *  PVOID KeyInformation
    *  ULONG Length
    *  PULONG ResultLength

Logging::

    B buffer ResultLength, KeyInformation


NtSaveKey
=========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** HANDLE FileHandle file_handle


NtSaveKeyEx
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** HANDLE FileHandle file_handle
    ** ULONG Format format
