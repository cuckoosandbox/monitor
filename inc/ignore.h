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

#ifndef MONITOR_IGNORE_H
#define MONITOR_IGNORE_H

#include <windows.h>
#include "ntapi.h"

void ignore_init();

int is_ignored_filepath(const wchar_t *fname);
int is_ignored_process();

void ignored_object_add(HANDLE object_handle);
void ignored_object_remove(HANDLE object_handle);
int is_ignored_object_handle(HANDLE object_handle);

int monitor_mode_should_propagate(const wchar_t *cmdline, uint32_t *mode);

#endif
