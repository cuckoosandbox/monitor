#ifndef MONITOR_IGNORE_H
#define MONITOR_IGNORE_H

#include <windows.h>
#include "ntapi.h"

BOOL is_ignored_file_unicode(const wchar_t *fname, int length);
BOOL is_ignored_file_objattr(const OBJECT_ATTRIBUTES *obj);

#endif
