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


NtOpenFile_DesiredAccess
========================

Inherits::

    NtCreateFile_DesiredAccess


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


ShareAccessFlags
================

Enum::

    FILE_SHARE_READ
    FILE_SHARE_WRITE
    FILE_SHARE_DELETE


NtCreateFile_ShareAccess
========================

Inherits::

    ShareAccessFlags


NtOpenFile_ShareAccess
======================

Inherits::

    ShareAccessFlags


NtCreateFile_CreateDisposition
==============================

Value::

    FILE_SUPERSEDE
    FILE_CREATE
    FILE_OPEN
    FILE_OPEN_IF
    FILE_OVERWRITE
    FILE_OVERWRITE_IF

NtCreateFile_IoStatusBlock_Information
======================================

Value::

    FILE_CREATED
    FILE_OPENED
    FILE_OVERWRITTEN
    FILE_SUPERSEDED
    FILE_EXISTS
    FILE_DOES_NOT_EXIST

FileOptions
===========

Enum::

    FILE_DIRECTORY_FILE
    FILE_NON_DIRECTORY_FILE
    FILE_WRITE_THROUGH
    FILE_SEQUENTIAL_ONLY
    FILE_RANDOM_ACCESS
    FILE_NO_INTERMEDIATE_BUFFERING
    FILE_SYNCHRONOUS_IO_ALERT
    FILE_SYNCHRONOUS_IO_NONALERT
    FILE_CREATE_TREE_CONNECTION
    FILE_COMPLETE_IF_OPLOCKED
    FILE_NO_EA_KNOWLEDGE
    FILE_OPEN_REPARSE_POINT
    FILE_DELETE_ON_CLOSE
    FILE_OPEN_BY_FILE_ID
    FILE_OPEN_FOR_BACKUP_INTENT
    FILE_RESERVE_OPFILTER


NtCreateFile_CreateOptions
==========================

Inherits::

    FileOptions


NtOpenFile_OpenOptions
======================

Inherits::

    FileOptions


SetFileAttributesW_dwFileAttributes
===================================

Enum::

    FILE_ATTRIBUTE_ARCHIVE
    FILE_ATTRIBUTE_HIDDEN
    FILE_ATTRIBUTE_NORMAL
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    FILE_ATTRIBUTE_OFFLINE
    FILE_ATTRIBUTE_READONLY
    FILE_ATTRIBUTE_SYSTEM
    FILE_ATTRIBUTE_TEMPORARY


SHGetFolderPathW_nFolder
========================

Value::

    CSIDL_ADMINTOOLS
    CSIDL_ALTSTARTUP
    CSIDL_APPDATA
    CSIDL_BITBUCKET
    CSIDL_CDBURN_AREA
    CSIDL_COMMON_ADMINTOOLS
    CSIDL_COMMON_ALTSTARTUP
    CSIDL_COMMON_APPDATA
    CSIDL_COMMON_DESKTOPDIRECTORY
    CSIDL_COMMON_DOCUMENTS
    CSIDL_COMMON_FAVORITES
    CSIDL_COMMON_MUSIC
    CSIDL_COMMON_OEM_LINKS
    CSIDL_COMMON_PICTURES
    CSIDL_COMMON_PROGRAMS
    CSIDL_COMMON_STARTMENU
    CSIDL_COMMON_STARTUP
    CSIDL_COMMON_TEMPLATES
    CSIDL_COMMON_VIDEO
    CSIDL_COMPUTERSNEARME
    CSIDL_CONNECTIONS
    CSIDL_CONTROLS
    CSIDL_COOKIES
    CSIDL_DESKTOP
    CSIDL_DESKTOPDIRECTORY
    CSIDL_DRIVES
    CSIDL_FAVORITES
    CSIDL_FONTS
    CSIDL_HISTORY
    CSIDL_INTERNET
    CSIDL_INTERNET_CACHE
    CSIDL_LOCAL_APPDATA
    CSIDL_MYDOCUMENTS
    CSIDL_MYMUSIC
    CSIDL_MYPICTURES
    CSIDL_MYVIDEO
    CSIDL_NETHOOD
    CSIDL_NETWORK
    CSIDL_PERSONAL
    CSIDL_PRINTERS
    CSIDL_PRINTHOOD
    CSIDL_PROFILE
    CSIDL_PROGRAM_FILES
    CSIDL_PROGRAM_FILESX86
    CSIDL_PROGRAM_FILES_COMMON
    CSIDL_PROGRAM_FILES_COMMONX86
    CSIDL_PROGRAMS
    CSIDL_RECENT
    CSIDL_RESOURCES
    CSIDL_RESOURCES_LOCALIZED
    CSIDL_SENDTO
    CSIDL_STARTMENU
    CSIDL_STARTUP
    CSIDL_SYSTEM
    CSIDL_SYSTEMX86
    CSIDL_TEMPLATES
    CSIDL_WINDOWS
