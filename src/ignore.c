#include <stdio.h>
#include <windows.h>
#include "ntapi.h"

#define IGNORE_MATCH(s) \
    if(!wcsnicmp(fname, s, length)) return TRUE

#define IGNORE_START(s) \
    if(!wcsnicmp(fname, s, sizeof(s)/sizeof(wchar_t)-1)) return TRUE

BOOL is_ignored_file_unicode(const wchar_t *fname, int length)
{
    IGNORE_MATCH(L"\\??\\PIPE\\lsarpc");
    IGNORE_MATCH(L"\\??\\MountPointManager");
    IGNORE_START(L"\\??\\IDE#");
    IGNORE_START(L"\\??\\STORAGE#");
    IGNORE_START(L"\\??\\root#");
    // IGNORE_START(L"\\Device\\");
    return FALSE;
}

BOOL is_ignored_file_objattr(const OBJECT_ATTRIBUTES *obj)
{
    return is_ignored_file_unicode(obj->ObjectName->Buffer,
        obj->ObjectName->Length / sizeof(wchar_t));
}

