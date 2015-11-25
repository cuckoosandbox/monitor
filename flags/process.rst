CreateProcessInternalW_creation_flags
=====================================

Inherits::

    PRIORITY_CLASS

Enum::

    CREATE_BREAKAWAY_FROM_JOB
    CREATE_DEFAULT_ERROR_MODE
    CREATE_NEW_CONSOLE
    CREATE_NEW_PROCESS_GROUP
    CREATE_NO_WINDOW
    CREATE_PROTECTED_PROCESS
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL
    CREATE_SEPARATE_WOW_VDM
    CREATE_SHARED_WOW_VDM
    CREATE_SUSPENDED
    CREATE_UNICODE_ENVIRONMENT
    DEBUG_ONLY_THIS_PROCESS
    DEBUG_PROCESS
    DETACHED_PROCESS
    EXTENDED_STARTUPINFO_PRESENT
    INHERIT_PARENT_AFFINITY


MemoryProtectionFlags
=====================

Enum::

    PAGE_EXECUTE
    PAGE_EXECUTE_READ
    PAGE_EXECUTE_READWRITE
    PAGE_EXECUTE_WRITECOPY
    PAGE_NOACCESS
    PAGE_READONLY
    PAGE_READWRITE
    PAGE_WRITECOPY
    PAGE_GUARD
    PAGE_NOCACHE
    PAGE_WRITECOMBINE


VirtualProtectEx_flNewProtect
=============================

Inherits::

    MemoryProtectionFlags


NtProtectVirtualMemory_NewAccessProtection
==========================================

Inherits::

    MemoryProtectionFlags


NtAllocateVirtualMemory_Protect
===============================

Inherits::

    MemoryProtectionFlags


NtMapViewOfSection_Win32Protect
===============================

Inherits::

    MemoryProtectionFlags


AllocationType
==============

Enum::

    MEM_COMMIT
    MEM_RESERVE
    MEM_RESET
    MEM_LARGE_PAGES
    MEM_PHYSICAL
    MEM_TOP_DOWN
    MEM_WRITE_WATCH


NtAllocateVirtualMemory_AllocationType
======================================

Inherits::

    AllocationType


NtMapViewOfSection_AllocationType
=================================

Inherits::

    AllocationType
