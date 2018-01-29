/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2012-2018 Cuckoo Foundation.

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

#ifndef MONITOR_PIPE_H
#define MONITOR_PIPE_H

//
// Pipe API
//
// The following Format Specifiers are available:
// z  -> (char *) -> zero-terminated ascii string
// Z  -> (wchar_t *) -> zero-terminated unicode string
// s  -> (int, char *) -> ascii string with length
// S  -> (int, wchar_t *) -> unicode string with length
// o  -> (UNICODE_STRING *) -> unicode string
// O  -> (OBJECT_ATTRIBUTES *) -> wrapper around unicode string
// d  -> (int) -> integer
// x  -> (int) -> hexadecimal integer
// X  -> (uint64_t) -> 64-bit hexadecimal integer
// p  -> (void *) -> pointer as hexadecimal
//

#include <stdint.h>

void pipe_init(const char *pipe_name, int pipe_pid);

int pipe(const char *fmt, ...);
int32_t pipe2(void *out, uint32_t outlen, const char *fmt, ...);

#define PIPE_MAX_TIMEOUT 10000

#if DEBUG
#define dpipe(fmt, ...) pipe(fmt, ##__VA_ARGS__)
#else
#define dpipe(fmt, ...) (void)0
#endif

#endif
