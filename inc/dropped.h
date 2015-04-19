/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2015 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef MONITOR_DROPPED_H
#define MONITOR_DROPPED_H

#include <windows.h>
#include "ntapi.h"

void dropped_init();
void dropped_add(HANDLE file_handle, const wchar_t *filepath);
void dropped_wrote(HANDLE file_handle);
void dropped_close(HANDLE file_handle);

#endif
