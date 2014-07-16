#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <winsock.h>
#include "bson.h"
#include "misc.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "utf8.h"

// TLS index of the bson object
static int g_tls_idx;

// the size of the logging buffer
#define BUFFERSIZE 1024 * 1024
#define BUFFER_LOG_MAX 4096

static CRITICAL_SECTION g_mutex;
static int g_sock;
static unsigned int g_starttick;


static void log_raw_direct(const char *buf, size_t length)
{
    if(g_sock < 0) return;

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

void log_explain()
{
    for (uint32_t idx = 0; g_explain_apinames[idx] != NULL; idx++) {
        bson b; char argidx[4];

        bson_init(&b);
        bson_append_int(&b, "I", idx);
        bson_append_string(&b, "name", g_explain_apinames[idx]);
        bson_append_string(&b, "type", "info");
        bson_append_string(&b, "category", g_explain_categories[idx]);

        bson_append_start_array(&b, "args");
        bson_append_string(&b, "0", "is_success");
        bson_append_string(&b, "1", "retval");

        const char *fmt = g_explain_paramtypes[idx];

        for (uint32_t argnum = 2; *fmt != 0; argnum++, fmt++) {
            snprintf(argidx, 4, "%d", argnum);

            const char *argname = g_explain_paramnames[idx][argnum-2];

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
        log_raw_direct(bson_data(&b), bson_size(&b));
        bson_destroy(&b);
    }
}

void log_api(int index, int is_success, int return_value,
    const char *fmt, ...)
{
    va_list args; char key = 0; char idx[4];
    va_start(args, fmt);

    bson b;

    bson_init(&b);
    bson_append_int(&b, "I", index);
    bson_append_int(&b, "T", GetCurrentThreadId());
    bson_append_int(&b, "t", GetTickCount() - g_starttick);
    bson_append_start_array(&b, "args");
    bson_append_int(&b, "0", is_success);
    bson_append_int(&b, "1", return_value);

    for (int argnum = 2; *fmt != 0; argnum++) {
        key = *fmt++;

        snprintf(idx, 4, "%u", argnum);

        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(&b, idx, s, -1);
        }
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) { s = ""; len = 0; }
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
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_wstring(&b, idx, str->Buffer, str->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'O') {
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
            unsigned long type = va_arg(args, unsigned long);
            unsigned long size = va_arg(args, unsigned long);
            unsigned char *data = va_arg(args, unsigned char *);

            if(type == REG_NONE) {
                log_string(&b, idx, "", 0);
            }
            else if(type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(&b, idx, value);
            }
            else if(type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(&b, idx, htonl(value));
            }
            else if(type == REG_EXPAND_SZ || type == REG_SZ) {
                log_buffer(&b, idx, data, size);
            }
            else {
                log_buffer(&b, idx, data, 0);
            }
        }
    }

    va_end(args);

    bson_append_finish_array(&b);
    bson_finish(&b);
    log_raw_direct(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

void log_new_process()
{
    wchar_t module_path[MAX_PATH];
    GetModuleFileNameW(NULL, module_path, ARRAYSIZE(module_path));

    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    log_api(0, 1, 0, "llllu", st.dwLowDateTime, st.dwHighDateTime,
        GetCurrentProcessId(), parent_process_id(), module_path);
}

void log_new_thread()
{
    log_api(1, 1, 0, "l", GetCurrentProcessId());
}

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg)
{
    log_api(2, success, 0, "lsss",
        GetCurrentThreadId(), subcategory, funcname, msg);
}

void log_init(unsigned int ip, unsigned short port)
{
    InitializeCriticalSection(&g_mutex);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(g_sock < 0) {
        pipe("CRITICAL:Error creating logging socket.");
        return;
    }

    struct sockaddr_in addr = {
        .sin_family         = AF_INET,
        .sin_addr.s_addr    = ip,
        .sin_port           = htons(port),
    };

    if(connect(g_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        pipe("CRITICAL:Error connecting to the host.");
        return;
    }

    g_tls_idx = TlsAlloc();

    log_raw_direct("BSON\n", 5);
    log_new_process();
    log_new_thread();
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    if(g_sock > 0) {
        closesocket(g_sock);
    }
}
