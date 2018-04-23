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

#ifndef MONITOR_UTF8_H
#define MONITOR_UTF8_H

#include <stdint.h>
#include <windows.h>

int utf8_encode(uint32_t x, uint8_t *out);
int utf8_decode_strn(const char *in, wchar_t *out, uint32_t len);
int utf8_length(uint32_t x);

int utf8_bytecnt_ascii(const char *s, int len);
int utf8_bytecnt_unicode(const wchar_t *s, int len);

char *utf8_string(const char *s, int len);
char *utf8_wstring(const wchar_t *s, int len);

#endif
