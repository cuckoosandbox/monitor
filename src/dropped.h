#ifndef MONITOR_DROPPED_H
#define MONITOR_DROPPED_H

#include <windows.h>
#include "ntapi.h"

// Mask that ignores files that are opened with read-only attributes.
#define DUMP_FILE_MASK \
    (GENERIC_WRITE | FILE_GENERIC_WRITE | FILE_WRITE_DATA | \
     FILE_APPEND_DATA | STANDARD_RIGHTS_WRITE | STANDARD_RIGHTS_ALL)

void dropped_add(HANDLE file_handle, OBJECT_ATTRIBUTES *obj);
void dropped_wrote(HANDLE file_handle);
void dropped_close(HANDLE file_handle);

#endif
