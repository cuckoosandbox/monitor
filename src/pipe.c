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
#include "misc.h"
#include "ntapi.h"
#include "pipe.h"
#include "utf8.h"

static char g_pipe_name[MAX_PATH];

static int _pipe_utf8x(char **out, unsigned short x)
{
    unsigned char buf[3];
    int len = utf8_encode(x, buf);
    if(*out != NULL) {
        memcpy(*out, buf, len);
        *out += len;
    }
    return len;
}

static int _pipe_ascii(char **out, const char *s, int len)
{
    int ret = 0;
    while (len-- != 0) {
        ret += _pipe_utf8x(out, *(unsigned char *) s++);
    }
    return ret;
}

static int _pipe_unicode(char **out, const wchar_t *s, int len)
{
    int ret = 0;
    while (len-- != 0) {
        ret += _pipe_utf8x(out, *(unsigned short *) s++);
    }
    return ret;
}

static int _pipe_sprintf(char *out, const char *fmt, va_list args)
{
    int ret = 0;
    while (*fmt != 0) {
        if(*fmt != '%') {
            ret += _pipe_utf8x(&out, *fmt++);
            continue;
        }
        if(*++fmt == 'z') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) return -1;

            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'Z') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) return -1;

            ret += _pipe_unicode(&out, s, lstrlenW(s));
        }
        else if(*fmt == 's') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) return -1;

            ret += _pipe_ascii(&out, s, len < 0 ? (int) strlen(s) : len);
        }
        else if(*fmt == 'S') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) return -1;

            ret += _pipe_unicode(&out, s, len < 0 ? (int) lstrlenW(s) : len);
        }
        else if(*fmt == 'o') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) return -1;

            ret += _pipe_unicode(&out, str->Buffer,
                str->Length / sizeof(wchar_t));
        }
        else if(*fmt == 'O') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) return -1;

            ret += _pipe_unicode(&out, obj->ObjectName->Buffer,
                obj->ObjectName->Length / sizeof(wchar_t));
        }
        else if(*fmt == 'd') {
            char s[32];
            sprintf(s, "%d", va_arg(args, int));
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'x') {
            char s[16];
            sprintf(s, "%x", va_arg(args, int));
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'X') {
            char s[32];
            uint64_t value = va_arg(args, uint64_t);
            sprintf(s, "%08x%08x", (uint32_t)(value >> 32), (uint32_t) value);
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        fmt++;
    }
    return ret;
}

void pipe_init(const char *pipe_name)
{
    strncpy(g_pipe_name, pipe_name, sizeof(g_pipe_name));
}

int pipe(const char *fmt, ...)
{
    if(g_pipe_name[0] == 0) {
        MessageBox(NULL, "Pipe has not been initialized yet!", "Error", 0);
        return -1;
    }

    va_list args;
    va_start(args, fmt);
    int len = _pipe_sprintf(NULL, fmt, args);
    if(len > 0) {
        char buf[len + 1];
        _pipe_sprintf(buf, fmt, args);
        va_end(args);

        if(CallNamedPipe(g_pipe_name, buf, len, buf, len,
                (unsigned long *) &len, PIPE_MAX_TIMEOUT) == FALSE) {
            return 0;
        }
    }
    return -1;
}

int pipe2(void *out, int *outlen, const char *fmt, ...)
{
    if(g_pipe_name[0] == 0) {
        MessageBox(NULL, "Pipe has not been initialized yet!", "Error", 0);
        return -1;
    }

    va_list args;
    va_start(args, fmt);
    int len = _pipe_sprintf(NULL, fmt, args);
    if(len > 0) {
        char buf[len + 1];
        _pipe_sprintf(buf, fmt, args);
        va_end(args);

        if(CallNamedPipe(g_pipe_name, buf, len, out, *outlen,
                (unsigned long *) outlen, PIPE_MAX_TIMEOUT) == FALSE) {
            return 0;
        }
    }
    return -1;
}
