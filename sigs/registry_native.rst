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
    ** PUNICODE_STRING Class class
    ** ULONG CreateOptions options
    *  PULONG Disposition

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);

Logging::

    O sub_key unistr


NtOpenKey
=========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);

Logging::

    O sub_key unistr


NtOpenKeyEx
===========

Parameters::

    ** PHANDLE KeyHandle key_handle
    ** ACCESS_MASK DesiredAccess access
    *  POBJECT_ATTRIBUTES ObjectAttributes
    ** ULONG OpenOptions options

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(ObjectAttributes);

Logging::

    O sub_key unistr


NtRenameKey
===========

Parameters::

    ** HANDLE KeyHandle key_handle
    ** PUNICODE_STRING NewName new_name


NtReplaceKey
============

Parameters::

    ** POBJECT_ATTRIBUTES NewHiveFileName newfilepath
    ** HANDLE KeyHandle
    ** POBJECT_ATTRIBUTES BackupHiveFileName backup_filepath


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
    ** PUNICODE_STRING ValueName value_name
    ** ULONG TitleIndex index
    ** ULONG Type reg_type
    *  PVOID Data
    *  ULONG DataSize

Logging::

    b buffer DataSize, Data


NtQueryValueKey
===============

Parameters::

    ** HANDLE KeyHandle key_handle
    ** PUNICODE_STRING ValueName value_name
    ** KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass class
    *  PVOID KeyValueInformation
    *  ULONG Length
    *  PULONG ResultLength

Logging::

    B buffer ResultLength, KeyValueInformation


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
    ** PUNICODE_STRING ValueName value_name


NtLoadKey
=========

Parameters::

    ** POBJECT_ATTRIBUTES TargetKey target_key
    *  POBJECT_ATTRIBUTES SourceFile

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(SourceFile);

Logging::

    O filepath unistr


NtLoadKey2
==========

Parameters::

    ** POBJECT_ATTRIBUTES TargetKey target_key
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(SourceFile);

Logging::

    O filepath unistr


NtLoadKeyEx
===========

Parameters::

    ** POBJECT_ATTRIBUTES TargetKey target_key
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key

Pre::

    UNICODE_STRING *unistr = unistr_from_objattr(SourceFile);

Logging::

    O filepath unistr


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
