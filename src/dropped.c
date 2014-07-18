#include <stdio.h>
#include <windows.h>
#include "ignore.h"
#include "misc.h"
#include "ntapi.h"

void dropped_add(HANDLE file_handle, const OBJECT_ATTRIBUTES *obj)
{
    wchar_t fname[MAX_PATH_PLUS_TOLERANCE]; uint32_t length;

    if(is_directory_objattr(obj) == 0 && is_ignored_file_objattr(obj) == 0) {
        length = path_from_object_attributes(
            obj, fname, MAX_PATH_PLUS_TOLERANCE);

        length = ensure_absolute_path(fname, fname, length);

        // TODO Cache the file.
    }
}

void dropped_wrote(HANDLE file_handle)
{
    // TODO Mark this file as being written to.
}

void dropped_close(HANDLE file_handle)
{
    // TODO Remove this handle - drop it if required.
}
