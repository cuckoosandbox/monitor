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
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "pipe.h"
#include "utf8.h"

static CRITICAL_SECTION g_cs;
static wchar_t g_pipe_name[MAX_PATH];
static HANDLE g_pipe_handle;
static int g_pipe_pid;

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
            char s[32]; uint32_t value = va_arg(args, uint32_t);
            ultostr(value, s, 10);
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'x') {
            char s[16]; uint32_t value = va_arg(args, uint32_t);
            ultostr(value, s, 16);
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'X') {
            char s[32]; uint64_t value = va_arg(args, uint64_t);
            ultostr((uint32_t)(value >> 32), s, 16);
            ultostr((uint32_t) value, s + strlen(s), 16);
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        else if(*fmt == 'p') {
            char s[32]; uintptr_t value = va_arg(args, uintptr_t);
            s[0] = '0', s[1] = 'x';
#if __x86_64__
            ultostr((uint32_t)(value >> 32), s + 2, 16);
            ultostr((uint32_t) value, s + strlen(s), 16);
#else
            ultostr(value, s + 2, 16);
#endif
            ret += _pipe_ascii(&out, s, strlen(s));
        }
        fmt++;
    }
    return ret;
}

static void open_pipe_handle()
{
    if(g_pipe_handle != INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        g_pipe_handle = CreateFileW(g_pipe_name, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);

        sleep(50);
    } while (g_pipe_handle == INVALID_HANDLE_VALUE);

    uint32_t pipe_mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    set_named_pipe_handle_mode(g_pipe_handle, pipe_mode);
}

void pipe_init(const char *pipe_name, int pipe_pid)
{
    InitializeCriticalSection(&g_cs);
    wcsncpyA(g_pipe_name, pipe_name, MAX_PATH);
    g_pipe_handle = INVALID_HANDLE_VALUE;
    g_pipe_pid = pipe_pid;
}

// Hack because _pipe_sprintf() works with va_list.
static int _prepend_pid(char *buf, ...)
{
    va_list args;
    va_start(args, buf);
    int ret = _pipe_sprintf(buf, "%d:", args);
    va_end(args);
    return ret;
}

int pipe(const char *fmt, ...)
{
#if DEBUG_STANDALONE
    va_list _args;
    va_start(_args, fmt);
    vprintf(fmt, _args);
    va_end(_args);
    return 0;
#endif

    if(g_pipe_name[0] == 0) {
        message_box(NULL, "Pipe has not been initialized yet!", "Error", 0);
        return -1;
    }

    open_pipe_handle();

    static char buf[0x10000]; va_list args; int ret = -1, len = 0;

    EnterCriticalSection(&g_cs);

    if(g_pipe_pid != 0) {
        len = _prepend_pid(buf, get_current_process_id());
    }

    va_start(args, fmt);
    len += _pipe_sprintf(buf+len, fmt, args);
    va_end(args);

    if(len > 0) {
        transact_named_pipe(g_pipe_handle, buf, len, buf, sizeof(buf), NULL);
        ret = 0;
    }

    LeaveCriticalSection(&g_cs);
    return ret;
}

int32_t pipe2(void *out, uint32_t outlen, const char *fmt, ...)
{
#if DEBUG_STANDALONE
    va_list _args;
    va_start(_args, fmt);
    vprintf(fmt, _args);
    va_end(_args);
    return 0;
#endif

    if(g_pipe_name[0] == 0) {
        message_box(NULL, "Pipe has not been initialized yet!", "Error", 0);
        return -1;
    }

    open_pipe_handle();

    static char buf[0x10000]; va_list args;
    int32_t ret = -1, len = 0; uintptr_t written;

    EnterCriticalSection(&g_cs);

    if(g_pipe_pid != 0) {
        len = _prepend_pid(buf, get_current_process_id());
    }

    va_start(args, fmt);
    len += _pipe_sprintf(buf+len, fmt, args);
    va_end(args);

    if(len > 0) {
        transact_named_pipe(g_pipe_handle, buf, len, out, outlen, &written);
        ret = written;
    }

    LeaveCriticalSection(&g_cs);
    return ret;
}
