/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2014 Cuckoo Foundation.

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

#ifndef MONITOR_UNHOOK_H
#define MONITOR_UNHOOK_H

#include <stdint.h>

void unhook_detect_add_region(const char *funcname, const uint8_t *addr,
    const uint8_t *orig, const uint8_t *our, uint32_t length);

int unhook_init_detection(int first_process);

#endif
