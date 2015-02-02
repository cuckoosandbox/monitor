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

#include <stdio.h>
#include <windows.h>
#include "memory.h"
#include "utf8.h"

int utf8_encode(unsigned short c, unsigned char *out)
{
    if(c < 0x80) {
        *out = c & 0x7f;
        return 1;
    }
    else if(c < 0x800) {
        out[0] = 0xc0 + ((c >> 6) & 0x1f);
        out[1] = 0x80 + (c & 0x3f);
        return 2;
    }
    else {
        out[0] = 0xe0 + ((c >> 12) & 0x0f);
        out[1] = 0x80 + ((c >> 6) & 0x3f);
        out[2] = 0x80 + (c & 0x3f);
        return 3;
    }
}

int utf8_length(unsigned short x)
{
    unsigned char buf[3];
    return utf8_encode(x, buf);
}

int utf8_bytecnt_ascii(const char *s, int len)
{
    if(len < 0) len = strlen(s);

    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

int utf8_bytecnt_unicode(const wchar_t *s, int len)
{
    if(len < 0) len = lstrlenW(s);

    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

char *utf8_string(const char *s, int len)
{
    if(len < 0) len = strlen(s);

    int encoded_length = utf8_bytecnt_ascii(s, len);
    char *utf8string = (char *) mem_alloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        pos += utf8_encode(*s++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}

char *utf8_wstring(const wchar_t *s, int len)
{
    if(len < 0) len = lstrlenW(s);

    int encoded_length = utf8_bytecnt_unicode(s, len);
    char *utf8string = (char *) mem_alloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        pos += utf8_encode(*s++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}
