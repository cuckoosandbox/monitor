#include <stdio.h>
#include <windows.h>
#include "ntapi.h"

ULONG_PTR parent_process_id() // By Napalm @ NetCore2K (rohitab.com)
{
    PROCESS_BASIC_INFORMATION pbi; ULONG ulSize = 0;
    LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        GetModuleHandle("ntdll"), "NtQueryInformationProcess");
    if(NtQueryInformationProcess == NULL) return 0;

    if(NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi,
            sizeof(pbi), &ulSize)) && ulSize == sizeof(pbi)) {
        return pbi.UniqueProcessId;
    }
    return 0;
}
