#include <stdio.h>
#include <windows.h>
#include "hashtable.h"
#include "ignore.h"
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"

#define HDDVOL1 L"\\Device\\HarddiskVolume1"

static ht_t g_files;
static CRITICAL_SECTION g_mutex;

typedef struct _dropped_entry_t {
    uint32_t written;
    uint32_t length;
    wchar_t path[MAX_PATH_PLUS_TOLERANCE];
} dropped_entry_t;

static void _dropped_submit(const wchar_t *path)
{
    // If the path is prepended with \??\, then we strip that.
    if(!wcsncmp(path, L"\\??\\", 4)) {
        pipe("FILE_NEW:%Z", path + 4);
    }

    // If the path is relative to a harddisk, such as C:a.txt, then we
    // have to get the current directory.
    else if(isalpha(path[0]) != 0 && path[1] == ':' &&
            path[2] != '/' && path[2] != '\\') {
        // TODO Handle this case correctly.
        pipe("FILE_NEW:%Z", path);
    }

    // \Device\HarddiskVolume1 is an alias for C:\.
    else if(!wcsnicmp(path, HDDVOL1, lstrlenW(HDDVOL1))) {
        pipe("FILE_NEW:C:%Z", path + lstrlenW(HDDVOL1));
    }

    // This should be an absolute path - send it straight away.
    else {
        pipe("FILE_NEW:%Z", path);
    }
}

void dropped_init()
{
    ht_init(&g_files, sizeof(dropped_entry_t));
    InitializeCriticalSection(&g_mutex);
}

void dropped_add(HANDLE file_handle, const OBJECT_ATTRIBUTES *obj)
{
    dropped_entry_t e;

    if(is_directory_objattr(obj) == 0 && is_ignored_file_objattr(obj) == 0) {
        e.length = path_from_object_attributes(
            obj, e.path, MAX_PATH_PLUS_TOLERANCE);

        e.length = ensure_absolute_path(e.path, e.path, e.length);

        EnterCriticalSection(&g_mutex);
        ht_insert(&g_files, (uintptr_t) file_handle, &e);
        LeaveCriticalSection(&g_mutex);
    }
}

void dropped_wrote(HANDLE file_handle)
{
    EnterCriticalSection(&g_mutex);

    dropped_entry_t *e = (dropped_entry_t *)
        ht_lookup(&g_files, (uintptr_t) file_handle, NULL);
    if(e != NULL) {
        _dropped_submit(e->path);
        ht_remove(&g_files, (uintptr_t) file_handle);
    }

    LeaveCriticalSection(&g_mutex);
}

void dropped_close(HANDLE file_handle)
{
    EnterCriticalSection(&g_mutex);

    ht_remove(&g_files, (uintptr_t) file_handle);

    LeaveCriticalSection(&g_mutex);
}
