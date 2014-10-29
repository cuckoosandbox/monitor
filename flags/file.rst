FILE_INFORMATION_CLASS
======================

Value::

    FileDirectoryInformation
    FileFullDirectoryInformation
    FileBothDirectoryInformation
    FileBasicInformation
    FileStandardInformation
    FileInternalInformation
    FileEaInformation
    FileAccessInformation
    FileNameInformation
    FileRenameInformation
    FileLinkInformation
    FileNamesInformation
    FileDispositionInformation
    FilePositionInformation
    FileFullEaInformation
    FileModeInformation
    FileAlignmentInformation
    FileAllInformation
    FileAllocationInformation
    FileEndOfFileInformation
    FileAlternateNameInformation
    FileStreamInformation
    FilePipeInformation
    FilePipeLocalInformation
    FilePipeRemoteInformation
    FileMailslotQueryInformation
    FileMailslotSetInformation
    FileCompressionInformation
    FileObjectIdInformation
    FileCompletionInformation
    FileMoveClusterInformation
    FileQuotaInformation
    FileReparsePointInformation
    FileNetworkOpenInformation
    FileAttributeTagInformation
    FileTrackingInformation
    FileIdBothDirectoryInformation
    FileIdFullDirectoryInformation
    FileValidDataLengthInformation
    FileShortNameInformation
    FileIoCompletionNotificationInformation
    FileIoStatusBlockRangeInformation
    FileIoPriorityHintInformation
    FileSfioReserveInformation
    FileSfioVolumeInformation
    FileHardLinkInformation
    FileProcessIdsUsingFileInformation
    FileNormalizedNameInformation
    FileNetworkPhysicalNameInformation
    FileIdGlobalTxDirectoryInformation
    FileIsRemoteDeviceInformation
    FileAttributeCacheInformation
    FileNumaNodeInformation
    FileStandardLinkInformation
    FileRemoteProtocolInformation


FILE_INFO_BY_HANDLE_CLASS
=========================

Value::

    FileBasicInfo
    FileStandardInfo
    FileNameInfo
    FileRenameInfo
    FileDispositionInfo
    FileAllocationInfo
    FileEndOfFileInfo
    FileStreamInfo
    FileCompressionInfo
    FileAttributeTagInfo
    FileIdBothDirectoryInfo
    FileIdBothDirectoryRestartInfo
    FileIoPriorityHintInfo
    FileRemoteProtocolInfo
    FileFullDirectoryInfo
    FileFullDirectoryRestartInfo
    FileStorageInfo
    FileAlignmentInfo
    FileIdInfo
    FileIdExtdDirectoryInfo
    FileIdExtdDirectoryRestartInfo


NtCreateFile_DesiredAccess
==========================

Inherits::

    ACCESS_MASK

Enum::

    FILE_READ_DATA
    FILE_READ_ATTRIBUTES
    FILE_READ_EA
    FILE_WRITE_DATA
    FILE_WRITE_ATTRIBUTES
    FILE_WRITE_EA
    FILE_APPEND_DATA
    FILE_EXECUTE
    FILE_LIST_DIRECTORY
    FILE_TRAVERSE


NtCreateFile_FileAttributes
===========================

Enum::

    FILE_ATTRIBUTE_ARCHIVE
    FILE_ATTRIBUTE_ENCRYPTED
    FILE_ATTRIBUTE_HIDDEN
    FILE_ATTRIBUTE_NORMAL
    FILE_ATTRIBUTE_OFFLINE
    FILE_ATTRIBUTE_READONLY
    FILE_ATTRIBUTE_SYSTEM
    FILE_ATTRIBUTE_TEMPORARY
    FILE_FLAG_BACKUP_SEMANTICS
    FILE_FLAG_DELETE_ON_CLOSE
    FILE_FLAG_NO_BUFFERING
    FILE_FLAG_OPEN_NO_RECALL
    FILE_FLAG_OPEN_REPARSE_POINT
    FILE_FLAG_OVERLAPPED
    FILE_FLAG_POSIX_SEMANTICS
    FILE_FLAG_RANDOM_ACCESS
    FILE_FLAG_SESSION_AWARE
    FILE_FLAG_SEQUENTIAL_SCAN
    FILE_FLAG_WRITE_THROUGH


NtCreateFile_ShareAccess
========================

Enum::

    FILE_SHARE_READ
    FILE_SHARE_WRITE
    FILE_SHARE_DELETE


NtCreateFile_CreateDisposition
==============================

Value::

    FILE_SUPERSEDE
    FILE_CREATE
    FILE_OPEN
    FILE_OPEN_IF
    FILE_OVERWRITE
    FILE_OVERWRITE_IF
