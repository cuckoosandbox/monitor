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

#include <stdio.h>
#include <windows.h>
#include "memory.h"
#include "utf8.h"

int utf8_encode(uint32_t c, uint8_t *out)
{
    if(c < 0x80) {
        *out = c & 0x7f;
        return 1;
    }
    if(c < 0x800) {
        out[0] = 0xc0 + ((c >>  6) & 0x1f);
        out[1] = 0x80 + ((c >>  0) & 0x3f);
        return 2;
    }
    if(c < 0x10000) {
        out[0] = 0xe0 + ((c >> 12) & 0x0f);
        out[1] = 0x80 + ((c >>  6) & 0x3f);
        out[2] = 0x80 + (c & 0x3f);
        return 3;
    }
    if(c < 0x200000) {
        out[0] = 0xf0 + ((c >> 18) & 0x07);
        out[1] = 0x80 + ((c >> 12) & 0x3f);
        out[2] = 0x80 + ((c >>  6) & 0x3f);
        out[3] = 0x80 + ((c >>  0) & 0x3f);
        return 4;
    }

    // The following two we won't be needing for UTF-16 encoding,
    // but while we're at it anyway..
    if(c < 0x4000000) {
        out[0] = 0xf8 + ((c >> 24) & 0x03);
        out[1] = 0x80 + ((c >> 18) & 0x3f);
        out[2] = 0x80 + ((c >> 12) & 0x3f);
        out[3] = 0x80 + ((c >>  6) & 0x3f);
        out[4] = 0x80 + ((c >>  0) & 0x3f);
        return 5;
    }
    if(c < 0x80000000) {
        out[0] = 0xfc + ((c >> 30) & 0x01);
        out[1] = 0x80 + ((c >> 24) & 0x3f);
        out[2] = 0x80 + ((c >> 18) & 0x3f);
        out[3] = 0x80 + ((c >> 12) & 0x3f);
        out[4] = 0x80 + ((c >>  6) & 0x3f);
        out[5] = 0x80 + ((c >>  0) & 0x3f);
        return 6;
    }
    return -1;
}

int utf8_decode_strn(const char *in, wchar_t *out, uint32_t len)
{
    const uint8_t *in_ = (const uint8_t *) in;
    const wchar_t *base = out; uint16_t ch;
    while (*in_ != 0 && --len != 0) {
        if((*in_ & 0x80) == 0) {
            *out++ = *in_++;
            continue;
        }
        if((*in_ & 0xe0) == 0xc0) {
            ch = *in_++ & 0x1f;
        }
        else if((*in_ & 0xf0) == 0xe0) {
            ch = *in_++ & 0xf;
        }
        else if((*in_ & 0xf8) == 0xf0) {
            ch = *in_++ & 0x7;
        }
        else {
            return -1;
        }

        // We assume validity.. ;-)
        while ((*in_ & 0xc0) == 0x80) {
            ch = (ch << 6) | (*in_++ & 0x3f);
        }
        *out++ = ch;
    }
    *out = 0;
    return out - base;
}

int utf8_length(uint32_t c)
{
    uint8_t buf[6];
    return utf8_encode(c, buf);
}

int utf8_bytecnt_ascii(const char *s, int len)
{
    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length((uint8_t) *s++);
    }
    return ret;
}

int utf8_bytecnt_unicode(const wchar_t *s, int len)
{
    int ret = 0;
    while (len-- != 0) {
        // Handle Supplementary Planes.
        if((uint16_t) *s >= 0xd800 && (uint16_t) *s < 0xdc00) {
            // No remaining space? Prevent possibly reading out of bounds.
            if(len == 0) {
                break;
            }

            uint32_t ch = ((uint32_t)(uint16_t) *s - 0xd800) << 10;

            // We'll just ignore invalid low surrogates..
            if((uint16_t) s[1] >= 0xdc00 && (uint16_t) s[1] < 0xe000) {
                ch += (uint16_t) s[1] - 0xdc00;
            }

            ret += utf8_length(ch);
            s += 2, len--;
        }
        else {
            ret += utf8_length((uint16_t) *s++);
        }
    }
    return ret;
}

char *utf8_string(const char *s, int len)
{
    int encoded_length = utf8_bytecnt_ascii(s, len);
    char *utf8string = (char *) mem_alloc(encoded_length+5);
    if(utf8string == NULL) {
        return NULL;
    }

    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        pos += utf8_encode((uint8_t) *s++, (uint8_t *) &utf8string[pos]);
    }
    utf8string[pos] = 0;
    return utf8string;
}

char *utf8_wstring(const wchar_t *s, int len)
{
    int encoded_length = utf8_bytecnt_unicode(s, len);
    char *utf8string = (char *) mem_alloc(encoded_length+5);
    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        // Handle Supplementary Planes.
        if((uint16_t) *s >= 0xd800 && (uint16_t) *s < 0xdc00) {
            // No remaining space? Prevent possibly reading out of bounds.
            if(len == 0) {
                break;
            }

            uint32_t ch = ((uint32_t)(uint16_t) *s - 0xd800) << 10;

            // We'll just ignore invalid low surrogates..
            if((uint16_t) s[1] >= 0xdc00 && (uint16_t) s[1] < 0xe000) {
                ch += (uint16_t) s[1] - 0xdc00;
            }

            pos += utf8_encode(ch, (uint8_t *) &utf8string[pos]);
            s += 2, len--;
        }
        else {
            pos += utf8_encode((uint16_t) *s++, (uint8_t *) &utf8string[pos]);
        }
    }
    utf8string[pos] = 0;
    return utf8string;
}
