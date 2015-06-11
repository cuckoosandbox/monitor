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

#ifndef MONITOR_DIFFING_H
#define MONITOR_DIFFING_H

#include <stdint.h>

//
// Diffing API
//
// The following Format Specifiers are available:
// s  -> (char *) -> zero-terminated ascii string
// S  -> (int, char *) -> ascii string with length
// u  -> (wchar_t *) -> zero-terminated unicode string
// U  -> (int, wchar_t *) -> unicode string with length
// i  -> (int) -> 32-bit integer
// I  -> (int *) -> pointer to a 32-bit integer
// l  -> (int) -> 32-bit integer
// L  -> (int *) -> pointer to a 32-bit integer
// p  -> (void *) -> pointer
// P  -> (void **) -> pointer to a pointer
// b  -> (int, void *) -> buffer with length
// h  -> (HANDLE) -> object handle to be checked against ignored object list
//

void diffing_init(const char *path, int enable);
uint64_t call_hash(const char *fmt, ...);
int is_interesting_hash(uint64_t hash);

#endif
