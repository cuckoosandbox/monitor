WINDOWS_HOOKS
=============

Value::

    WH_JOURNALRECORD
    WH_JOURNALPLAYBACK
    WH_KEYBOARD
    WH_GETMESSAGE
    WH_CALLWNDPROC
    WH_CBT
    WH_SYSMSGFILTER
    WH_MOUSE
    WH_HARDWARE
    WH_DEBUG
    WH_SHELL
    WH_FOREGROUNDIDLE
    WH_CALLWNDPROCRET
    WH_KEYBOARD_LL
    WH_MOUSE_LL


SetWindowsHookExA_idHook
========================

Inherits::

    WINDOWS_HOOKS


SetWindowsHookExW_idHook
========================

Inherits::

    WINDOWS_HOOKS


SetErrorMode_uMode
==================

Enum::

    SEM_FAILCRITICALERRORS
    SEM_NOALIGNMENTFAULTEXCEPT
    SEM_NOGPFAULTERRORBOX
    SEM_NOOPENFILEERRORBOX


NtQuerySystemInformation_SystemInformationClass
===============================================

Value::

    SystemBasicInformation
    SystemProcessorInformation
    SystemPerformanceInformation
    SystemTimeOfDayInformation
    SystemPathInformation
    SystemProcessInformation
    SystemCallCountInformation
    SystemDeviceInformation
    SystemProcessorPerformanceInformation
    SystemFlagsInformation
    SystemCallTimeInformation
    SystemModuleInformation
    SystemLocksInformation
    SystemStackTraceInformation
    SystemPagedPoolInformation
    SystemNonPagedPoolInformation
    SystemHandleInformation
    SystemObjectInformation
    SystemPageFileInformation
    SystemVdmInstemulInformation
    SystemVdmBopInformation
    SystemFileCacheInformation
    SystemPoolTagInformation
    SystemInterruptInformation
    SystemDpcBehaviorInformation
    SystemFullMemoryInformation
    SystemLoadGdiDriverInformation
    SystemUnloadGdiDriverInformation
    SystemTimeAdjustmentInformation
    SystemSummaryMemoryInformation
    SystemMirrorMemoryInformation
    SystemPerformanceTraceInformation
    SystemObsolete0
    SystemExceptionInformation
    SystemCrashDumpStateInformation
    SystemKernelDebuggerInformation
    SystemContextSwitchInformation
    SystemRegistryQuotaInformation
    SystemExtendServiceTableInformation
    SystemPrioritySeperation
    SystemVerifierAddDriverInformation
    SystemVerifierRemoveDriverInformation
    SystemProcessorIdleInformation
    SystemLegacyDriverInformation
    SystemCurrentTimeZoneInformation
    SystemLookasideInformation
    SystemTimeSlipNotification
    SystemSessionCreate
    SystemSessionDetach
    SystemSessionInformation
    SystemRangeStartInformation
    SystemVerifierInformation
    SystemVerifierThunkExtend
    SystemSessionProcessInformation
    SystemLoadGdiDriverInSystemSpace
    SystemNumaProcessorMap
    SystemPrefetcherInformation
    SystemExtendedProcessInformation
    SystemRecommendedSharedDataAlignment
    SystemComPlusPackage
    SystemNumaAvailableMemory
    SystemProcessorPowerInformation
    SystemEmulationBasicInformation
    SystemEmulationProcessorInformation
    SystemExtendedHandleInformation
    SystemLostDelayedWriteInformation
    SystemBigPoolInformation
    SystemSessionPoolTagInformation
    SystemSessionMappedViewInformation
    SystemHotpatchInformation
    SystemObjectSecurityMode
    SystemWatchdogTimerHandler
    SystemWatchdogTimerInformation
    SystemLogicalProcessorInformation
    SystemWow64SharedInformationObsolete
    SystemRegisterFirmwareTableInformationHandler
    SystemFirmwareTableInformation
    SystemModuleInformationEx
    SystemVerifierTriageInformation
    SystemSuperfetchInformation
    SystemMemoryListInformation
    SystemFileCacheInformationEx
    SystemThreadPriorityClientIdInformation
    SystemProcessorIdleCycleTimeInformation
    SystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx
    SystemRefTraceInformation
    SystemSpecialPoolInformation
    SystemProcessIdInformation
    SystemErrorPortInformation
    SystemBootEnvironmentInformation
    SystemHypervisorInformation
    SystemVerifierInformationEx
    SystemTimeZoneInformation
    SystemImageFileExecutionOptionsInformation
    SystemCoverageInformation
    SystemPrefetchPatchInformation
    SystemVerifierFaultsInformation
    SystemSystemPartitionInformation
    SystemSystemDiskInformation
    SystemProcessorPerformanceDistribution
    SystemNumaProximityNodeInformation
    SystemDynamicTimeZoneInformation
    SystemCodeIntegrityInformation
    SystemProcessorMicrocodeUpdateInformation
    SystemProcessorBrandString
    SystemVirtualAddressInformation
    SystemLogicalProcessorAndGroupInformation
    SystemProcessorCycleTimeInformation
    SystemStoreInformation
    SystemRegistryAppendString
    SystemAitSamplingValue
    SystemVhdBootInformation
    SystemCpuQuotaInformation
    SystemNativeBasicInformation
    SystemErrorPortTimeouts
    SystemLowPriorityIoInformation
    SystemBootEntropyInformation
    SystemVerifierCountersInformation
    SystemPagedPoolInformationEx
    SystemSystemPtesInformationEx
    SystemNodeDistanceInformation
    SystemAcpiAuditInformation
    SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation
    SystemSessionBigPoolInformation
    SystemBootGraphicsInformation
    SystemScrubPhysicalMemoryInformation
    SystemBadPageInformation
    SystemProcessorProfileControlArea
    SystemCombinePhysicalMemoryInformation
    SystemEntropyInterruptTimingInformation
    SystemConsoleInformation
    SystemPlatformBinaryInformation
    SystemPolicyInformation
    SystemHypervisorProcessorCountInformation
    SystemDeviceDataInformation
    SystemDeviceDataEnumerationInformation
    SystemMemoryTopologyInformation
    SystemMemoryChannelInformation
    SystemBootLogoInformation
    SystemProcessorPerformanceInformationEx
    SystemSpare0
    SystemSecureBootPolicyInformation
    SystemPageFileInformationEx
    SystemSecureBootInformation
    SystemEntropyInterruptTimingRawInformation
    SystemPortableWorkspaceEfiLauncherInformation
    SystemFullProcessInformation
    SystemKernelDebuggerInformationEx
    SystemBootMetadataInformation
    SystemSoftRebootInformation
    SystemElamCertificateInformation
    SystemOfflineDumpConfigInformation
    SystemProcessorFeaturesInformation
    SystemRegistryReconciliationInformation
    SystemEdidInformation


NtShutdownSystem_Action
=======================

Value::

    ShutdownNoReboot
    ShutdownReboot
    ShutdownPowerOff
