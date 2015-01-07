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

#ifndef MONITOR_SLEEP_H
#define MONITOR_SLEEP_H

#include <stdint.h>
#include <windows.h>

void sleep_init(int first_process, uint32_t force_skip,
    uint32_t startup_time);

int sleep_skip(LARGE_INTEGER *delay);

void sleep_skip_disable();

void sleep_apply_filetime(FILETIME *ft);
void sleep_apply_systemtime(SYSTEMTIME *st);
uint64_t sleep_skipped();

#endif
