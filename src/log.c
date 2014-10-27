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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <winsock2.h>
#include <windows.h>
#include <winsock.h>
#include "bson/bson.h"
#include "hooking.h"
#include "hook-info.h"
#include "misc.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "symbol.h"
#include "utf8.h"

typedef struct _memblock_t {
    uint32_t length;
    void    *buffer;
} memblock_t;

// TLS index of the prelog buffer object.
static int g_tls_idx;

// TLS index to see whether a thread is new or not.
static int g_thread_init_idx;

// Maximum length of a buffer so we try to avoid polluting logs with garbage.
#define BUFFER_LOG_MAX 4096

static CRITICAL_SECTION g_mutex;
static SOCKET g_sock = INVALID_SOCKET;
static unsigned int g_starttick;
static uint8_t g_api_init[MONITOR_HOOKCNT];

static void log_raw(const char *buf, size_t length)
{
    if(g_sock == INVALID_SOCKET) return;

    EnterCriticalSection(&g_mutex);

    size_t sent = 0; int ret;
    while (sent < length) {
        ret = send(g_sock, buf + sent, length - sent, 0);
        if(ret < 1) {
            pipe("CRITICAL:Error sending logs, send() returned %d.", ret);
            return;
        }
        sent += ret;
    }

    LeaveCriticalSection(&g_mutex);
}

static void log_int32(bson *b, const char *idx, int value)
{
    bson_append_int(b, idx, value);
}

static void log_int64(bson *b, const char *idx, int64_t value)
{
    bson_append_long(b, idx, value);
}

static void log_string(bson *b, const char *idx, const char *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    int ret, utf8len;

    char *utf8s = utf8_string(str, length);
    utf8len = *(int *) utf8s;
    ret = bson_append_binary(b, idx, BSON_BIN_BINARY, utf8s+4, utf8len);
    if(ret == BSON_ERROR) {
        pipe("CRITICAL:Error creating bson string, error, %x utf8len %d.",
            b->err, utf8len);
    }
    free(utf8s);
}

static void log_wstring(bson *b, const char *idx,
    const wchar_t *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    int ret, utf8len;
    char *utf8s = utf8_wstring(str, length);
    utf8len = *(int *) utf8s;
    ret = bson_append_binary(b, idx, BSON_BIN_BINARY, utf8s+4, utf8len);
    if(ret == BSON_ERROR) {
        pipe("CRITICAL:Error creating bson wstring, error %x, utf8len %d.",
            b->err, utf8len);
    }
    free(utf8s);
}

static void log_argv(bson *b, const char *idx, int argc, const char **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        snprintf(index, 5, "%u", i);
        log_string(b, index, argv[i], -1);
    }
    bson_append_finish_array(b);
}

static void log_wargv(bson *b, const char *idx,
    int argc, const wchar_t **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        snprintf(index, 5, "%u", i);
        log_wstring(b, index, argv[i], -1);
    }

    bson_append_finish_array(b);
}

static void log_buffer(bson *b, const char *idx,
    const uint8_t *buf, size_t length)
{
    size_t trunclength = min(length, BUFFER_LOG_MAX);

    if(buf == NULL) {
        trunclength = 0;
    }

    bson_append_binary(b, idx, BSON_BIN_BINARY,
        (const char *) buf, trunclength);
}

void log_explain(int index)
{
    bson b; char argidx[4];

    bson_init(&b);
    bson_append_int(&b, "I", index);
    bson_append_string(&b, "name", g_explain_apinames[index]);
    bson_append_string(&b, "type", "info");
    bson_append_string(&b, "category", g_explain_categories[index]);

    bson_append_start_array(&b, "args");
    bson_append_string(&b, "0", "is_success");
    bson_append_string(&b, "1", "retval");

    const char *fmt = g_explain_paramtypes[index];

    for (uint32_t argnum = 2; *fmt != 0; argnum++, fmt++) {
        snprintf(argidx, 4, "%d", argnum);

        const char *argname = g_explain_paramnames[index][argnum-2];

        // On certain formats, we need to tell cuckoo about them for
        // nicer display / matching.
        if(*fmt == 'p' || *fmt == 'P') {
            bson_append_start_array(&b, argidx);
            bson_append_string(&b, "0", argname);
            bson_append_string(&b, "1", "p");
            bson_append_finish_array(&b);
        }
        else {
            bson_append_string(&b, argidx, argname);
        }
    }

    bson_append_finish_array(&b);
    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

void log_api_pre(uint32_t length, const void *buffer)
{
    void *dup = memdup(buffer, length);
    memblock_t *mb = (memblock_t *) malloc(sizeof(memblock_t));
    if(mb != NULL) {
        mb->buffer = dup;
        mb->length = length;
        TlsSetValue(g_tls_idx, mb);
    }
}

#if DEBUG

#if !__x86_64__

static inline uintptr_t get_ebp()
{
    uintptr_t ret;
    __asm__ volatile("movl %%ebp, %0" : "=r" (ret));
    return ret;
}

#endif

static void _log_stacktrace(bson *b)
{
    uintptr_t addrs[32]; uint32_t count = 0; char number[20], sym[512];

    bson_append_start_array(b, "s");

#if !__x86_64__
    count = stacktrace(get_ebp(), addrs, sizeof(addrs) / sizeof(uintptr_t));
#endif

    for (uint32_t idx = 3; idx < count; idx++) {
        sprintf(number, "%d", idx);

#if __x86_64__
        sym[0] = 0;
#else
        symbol((const uint8_t *) addrs[idx], sym, sizeof(sym)-32);
#endif
        if(sym[0] != 0) {
            strcat(sym, " @ ");
        }

        sprintf(sym + strlen(sym), "0x%p", (const uint8_t *) addrs[idx]);

        bson_append_string(b, number, sym);
    }

    bson_append_finish_array(b);
}

#endif

void log_api(int index, int is_success, uintptr_t return_value,
    const char *fmt, ...)
{
    va_list args; char key = 0; char idx[4];
    va_start(args, fmt);

    EnterCriticalSection(&g_mutex);

    if(g_api_init[index] == 0) {
        log_explain(index);
        g_api_init[index] = 1;
    }

    LeaveCriticalSection(&g_mutex);

    void *value = TlsGetValue(g_thread_init_idx);
    if(value == NULL && index >= MONITOR_FIRSTHOOKIDX) {
        log_new_thread();
        TlsSetValue(g_thread_init_idx, "init!");
    }

    bson b;

    bson_init(&b);
    bson_append_int(&b, "I", index);
    bson_append_int(&b, "T", GetCurrentThreadId());
    bson_append_int(&b, "t", GetTickCount() - g_starttick);

#if DEBUG
    _log_stacktrace(&b);
#endif

    bson_append_start_array(&b, "args");
    bson_append_int(&b, "0", is_success);
    bson_append_long(&b, "1", return_value);

    int argnum = 2;

    memblock_t *mb = (memblock_t *) TlsGetValue(g_tls_idx);
    if(mb != NULL) {
        snprintf(idx, 4, "%u", argnum++);

        log_buffer(&b, idx, mb->buffer, mb->length);
        free(mb->buffer);
        free(mb);

        TlsSetValue(g_tls_idx, NULL);
    }

    while (*fmt != 0) {
        key = *fmt++;

        snprintf(idx, 4, "%u", argnum++);

        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(&b, idx, s, -1);
        }
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "", len = 0;
            log_string(&b, idx, s, len);
        }
        else if(key == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(&b, idx, s, -1);
        }
        else if(key == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"", len = 0;
            log_wstring(&b, idx, s, len);
        }
        else if(key == 'b') {
            size_t len = va_arg(args, size_t);
            const uint8_t *s = va_arg(args, const uint8_t *);
            log_buffer(&b, idx, s, len);
        }
        else if(key == 'B') {
            size_t *len = va_arg(args, size_t *);
            const uint8_t *s = va_arg(args, const uint8_t *);
            log_buffer(&b, idx, s, len == NULL ? 0 : *len);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_int32(&b, idx, value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_int32(&b, idx, value);
        }
        else if(key == 'L' || key == 'P') {
            long *ptr = va_arg(args, long *);
            log_int32(&b, idx, ptr != NULL ? *ptr : 0);
        }
        else if(key == 'o') {
            ANSI_STRING *str = va_arg(args, ANSI_STRING *);
            if(str == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_string(&b, idx, str->Buffer, str->Length);
            }
        }
        else if(key == 'O') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_wstring(&b, idx, str->Buffer,
                    str->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'x') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_wstring(&b, idx, obj->ObjectName->Buffer,
                    obj->ObjectName->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(&b, idx, argc, argv);
        }
        else if(key == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(&b, idx, argc, argv);
        }
        else if(key == 'r' || key == 'R') {
            uint32_t *type = va_arg(args, uint32_t *);
            uint32_t *size = va_arg(args, uint32_t *);
            uint8_t *data = va_arg(args, uint8_t *);

            uint32_t _type = REG_NONE, _size = 0;

            if(type == NULL) {
                type = &_type;
            }
            if(size == NULL) {
                size = &_size;
            }

            if(*type == REG_NONE) {
                log_string(&b, idx, NULL, 0);
            }
            else if(*type == REG_DWORD || *type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(&b, idx, value);
            }
            else if(*type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(&b, idx, htonl(value));
            }
            else if(*type == REG_EXPAND_SZ || *type == REG_SZ) {
                if(key == 'r') {
                    log_string(&b, idx, (const char *) data, *size);
                }
                else {
                    log_wstring(&b, idx, (const wchar_t *) data, *size);
                }
            }
            else {
                log_buffer(&b, idx, data, *size);
            }
        }
        else if(key == 'q') {
            int64_t value = va_arg(args, int64_t);
            log_int64(&b, idx, value);
        }
        else if(key == 'Q') {
            LARGE_INTEGER *value = va_arg(args, LARGE_INTEGER *);
            log_int64(&b, idx, value != NULL ? value->QuadPart : 0);
        }
        else if(key == 'z') {
            bson *value = va_arg(args, bson *);
            if(value == NULL) {
                bson_append_null(&b, idx);
            }
            else {
                bson_append_bson(&b, idx, value);
            }
        }
        else if(key == 'c') {
            wchar_t buf[64];
            REFCLSID rclsid = va_arg(args, REFCLSID);
            clsid_to_string(rclsid, buf);
            log_wstring(&b, idx, buf, -1);
        }
        else {
            char buf[2] = {key, 0};
            pipe("CRITICAL:Invalid format specifier: %z", buf);
        }
    }

    va_end(args);

    bson_append_finish_array(&b);
    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

void log_new_process()
{
    wchar_t module_path[MAX_PATH];
    GetModuleFileNameW(NULL, module_path, ARRAYSIZE(module_path));
    GetLongPathNameW(module_path, module_path, ARRAYSIZE(module_path));

    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    log_api(0, 1, 0, "llllu", st.dwLowDateTime, st.dwHighDateTime,
        GetCurrentProcessId(), parent_process_id(), module_path);
}

void log_new_thread()
{
    // We temporarily pop any value off the TLS while logging the new thread.
    // (To handle the first API called on a thread using prelog).
    void *value = TlsGetValue(g_tls_idx);
    TlsSetValue(g_tls_idx, NULL);

    log_api(1, 1, 0, "l", GetCurrentProcessId());

    TlsSetValue(g_tls_idx, value);
}

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg)
{
    log_api(2, success, 0, "lsss",
        GetCurrentThreadId(), subcategory, funcname, msg);
}

void log_init(uint32_t ip, uint16_t port)
{
    InitializeCriticalSection(&g_mutex);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Might be the case when debugging manually, but should never happen
    // during an actual analysis.
    if(ip == 0 || port == 0) {
        pipe("CRITICAL:No connection information found!");
        return;
    }

    g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(g_sock == INVALID_SOCKET) {
        pipe("CRITICAL:Error creating logging socket.");
        return;
    }

    struct sockaddr_in addr = {
        .sin_family         = AF_INET,
        .sin_addr.s_addr    = ip,
        .sin_port           = htons(port),
    };

    if(connect(g_sock, (struct sockaddr *) &addr,
            sizeof(addr)) == SOCKET_ERROR) {
        pipe("CRITICAL:Error connecting to the host.");
        g_sock = -1;
        return;
    }

    g_tls_idx = TlsAlloc();
    g_thread_init_idx = TlsAlloc();

    log_raw("BSON\n", 5);
    log_new_process();
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    if(g_sock > 0) {
        closesocket(g_sock);
    }
}
