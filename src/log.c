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
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <winsock2.h>
#include <windows.h>
#include <winsock.h>
#include "bson/bson.h"
#include "flags.h"
#include "hooking.h"
#include "hook-info.h"
#include "memory.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "symbol.h"
#include "utf8.h"

// Maximum length of a buffer so we try to avoid polluting logs with garbage.
#define BUFFER_LOG_MAX 4096
#define EXCEPTION_MAXCOUNT 1024

static CRITICAL_SECTION g_mutex;
static SOCKET g_sock = INVALID_SOCKET;
static unsigned int g_starttick;
static uint8_t g_api_init[MONITOR_HOOKCNT];
static int g_log_exception;

static void _log_exception_perform();

// http://stackoverflow.com/questions/9655202/how-to-convert-integer-to-string-in-c
static void ultostr(int32_t value, char *str)
{
    const char digits[] = "0123456789";

    // Negative values.
    if(value < 0) {
        *str++ = '-';
        value = -value;
    }

    // Calculate the amount of numbers required.
    int shifter = value;
    do {
        str++, shifter /= 10;
    } while (shifter);

    // Populate the string.
    *str = 0;
    do {
        *--str = digits[value % 10];
        value /= 10;
    } while (value);
}

static void log_raw(const char *buf, size_t length)
{
    if(g_sock == INVALID_SOCKET) {
        char filepath[MAX_PATH];
        sprintf(filepath, "%s\\monitor.log", getenv("TEMP"));

        FILE *fp = fopen(filepath, "ab");
        if(fp == NULL) {
            static int count = 0;
            if(count++ < 3) {
                MessageBox(NULL, "Error opening debug logfile!", "Error", 0);
            }
            return;
        }
        fwrite(buf, 1, length, fp);
        fclose(fp);
        return;
    }

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
    mem_free(utf8s);
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
    mem_free(utf8s);
}

static void log_argv(bson *b, const char *idx, int argc, const char **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        ultostr(i, index);
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
        ultostr(i, index);
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

void log_explain(signature_index_t index)
{
    bson b; char argidx[4];

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_string(&b, "name", g_explain_apinames[index]);
    bson_append_string(&b, "type", "info");
    bson_append_string(&b, "category", g_explain_categories[index]);

    bson_append_start_array(&b, "args");
    bson_append_string(&b, "0", "is_success");
    bson_append_string(&b, "1", "retval");

    const char *fmt = g_explain_paramtypes[index];

    for (uint32_t argnum = 2; *fmt != 0; argnum++, fmt++) {
        ultostr(argnum, argidx);

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
    bson_append_start_object(&b, "flags");

    static const char *types[] = {
        [FLAGTYP_NONE] = "none",
        [FLAGTYP_ENUM] = "enum",
        [FLAGTYP_VALUE] = "value",
    };

    for (uint32_t idx = 0; g_api_flags[index][idx] != FLAG_NONE; idx++) {
        const flag_repr_t *f = g_flags[g_api_flags[index][idx]];
        bson_append_start_array(&b, g_api_flagnames[index][idx]);

        for (uint32_t idx2 = 0; f->type != FLAGTYP_NONE; idx2++, f++) {
            ultostr(idx, argidx);
            bson_append_start_array(&b, argidx);
            bson_append_string(&b, "0", types[f->type]);
            bson_append_int(&b, "1", f->value);
            bson_append_string(&b, "2", f->repr);
            bson_append_finish_array(&b);
        }

        bson_append_finish_array(&b);
    }

    bson_append_finish_object(&b);
    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

#if DEBUG

static void _log_stacktrace(bson *b)
{
    uintptr_t addrs[RETADDRCNT], count;
    char number[20], sym[512];

    bson_append_start_array(b, "s");

    count = stacktrace(NULL, addrs, RETADDRCNT, STACKTRACE_NOSTARTINMONITOR);

    for (uint32_t idx = 0; idx < count; idx++) {
        ultostr(idx-3, number);

        symbol((const uint8_t *) addrs[idx], sym, sizeof(sym)-32);
        if(sym[0] != 0) {
            strcat(sym, " @ ");
        }

        sprintf(sym + strlen(sym), "0x%p", (const uint8_t *) addrs[idx]);
        bson_append_string(b, number, sym);
    }

    bson_append_finish_array(b);
}

#endif

void log_api(signature_index_t index, int is_success, uintptr_t return_value,
    uint64_t hash, ...)
{
    va_list args; char idx[4];
    va_start(args, hash);

    EnterCriticalSection(&g_mutex);

    // If there is an exception available for processing, then process it now.
    if(g_log_exception != 0) {
        dpipe("INFO:Found exception - reporting it!");
        _log_exception_perform();
    }

    if(g_api_init[index] == 0) {
        log_explain(index);
        g_api_init[index] = 1;
    }

    LeaveCriticalSection(&g_mutex);

    bson b;

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_int(&b, "T", GetCurrentThreadId());
    bson_append_int(&b, "t", GetTickCount() - g_starttick);
    bson_append_long(&b, "h", hash);

#if DEBUG
    _log_stacktrace(&b);
#endif

    bson_append_start_array(&b, "args");
    bson_append_int(&b, "0", is_success);
    bson_append_long(&b, "1", return_value);

    int argnum = 2;

    for (const char *fmt = g_explain_paramtypes[index]; *fmt != 0; fmt++) {
        ultostr(argnum++, idx);

        if(*fmt == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(&b, idx, s, -1);
        }
        else if(*fmt == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "", len = 0;
            log_string(&b, idx, s, len);
        }
        else if(*fmt == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(&b, idx, s, -1);
        }
        else if(*fmt == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"", len = 0;
            log_wstring(&b, idx, s, len);
        }
        else if(*fmt == 'b') {
            size_t len = va_arg(args, size_t);
            const uint8_t *s = va_arg(args, const uint8_t *);
            log_buffer(&b, idx, s, len);
        }
        else if(*fmt == 'B') {
            size_t *len = va_arg(args, size_t *);
            const uint8_t *s = va_arg(args, const uint8_t *);
            log_buffer(&b, idx, s, len == NULL ? 0 : *len);
        }
        else if(*fmt == 'i') {
            int value = va_arg(args, int);
            log_int32(&b, idx, value);
        }
        else if(*fmt == 'l' || *fmt == 'p') {
            long value = va_arg(args, long);
            log_int32(&b, idx, value);
        }
        else if(*fmt == 'L' || *fmt == 'P') {
            long *ptr = va_arg(args, long *);
            log_int32(&b, idx, ptr != NULL ? *ptr : 0);
        }
        else if(*fmt == 'o') {
            ANSI_STRING *str = va_arg(args, ANSI_STRING *);
            if(str == NULL) {
                log_string(&b, idx, "", 0);
            }
            else {
                log_string(&b, idx, str->Buffer, str->Length);
            }
        }
        else if(*fmt == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(&b, idx, argc, argv);
        }
        else if(*fmt == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(&b, idx, argc, argv);
        }
        else if(*fmt == 'r' || *fmt == 'R') {
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
            else if(*type == REG_EXPAND_SZ || *type == REG_SZ ||
                    *type == REG_MULTI_SZ) {
                if(*fmt == 'r') {
                    uint32_t length = *size;
                    // Strings tend to be zero-terminated twice, so check for
                    // that and if that's the case, then ignore the trailing
                    // nullbyte.
                    if(data != NULL &&
                            strlen((const char *) data) == length - 1) {
                        length--;
                    }
                    log_string(&b, idx, (const char *) data, length);
                }
                else {
                    int32_t length = *size / sizeof(wchar_t);
                    // Strings tend to be zero-terminated twice, so check for
                    // that and if that's the case, then ignore the trailing
                    // nullbyte.
                    if(data != NULL &&
                            lstrlenW((const wchar_t *) data) == length - 1) {
                        length--;
                    }
                    log_wstring(&b, idx, (const wchar_t *) data, length);
                }
            }
            else if(*type == REG_QWORD || *type == REG_QWORD_LITTLE_ENDIAN) {
                uint64_t value = *(uint64_t *) data;
                log_int64(&b, idx, value);
            }
            else {
                log_buffer(&b, idx, data, *size);
            }
        }
        else if(*fmt == 'q') {
            int64_t value = va_arg(args, int64_t);
            log_int64(&b, idx, value);
        }
        else if(*fmt == 'Q') {
            LARGE_INTEGER *value = va_arg(args, LARGE_INTEGER *);
            log_int64(&b, idx, value != NULL ? value->QuadPart : 0);
        }
        else if(*fmt == 'z') {
            bson *value = va_arg(args, bson *);
            if(value == NULL) {
                bson_append_null(&b, idx);
            }
            else {
                bson_append_bson(&b, idx, value);
            }
        }
        else if(*fmt == 'c') {
            wchar_t buf[64];
            REFCLSID rclsid = va_arg(args, REFCLSID);
            clsid_to_string(rclsid, buf);
            log_wstring(&b, idx, buf, -1);
        }
        else {
            char buf[2] = {*fmt, 0};
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
    wchar_t *module_path = get_unicode_buffer();
    GetModuleFileNameW(NULL, module_path, MAX_PATH_W);
    GetLongPathNameW(module_path, module_path, MAX_PATH_W);

    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    log_api(SIG___process__, 1, 0, 0, st.dwLowDateTime,
        st.dwHighDateTime, get_current_process_id(),
        parent_process_id(), module_path);
}

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg)
{
    log_api(SIG___anomaly__, success, 0, 0,
        GetCurrentThreadId(), subcategory, funcname, msg);
}

static uintptr_t g_exception_return_addresses[32];
static uint32_t g_exception_return_address_count;
static CONTEXT g_exception_context;
static EXCEPTION_RECORD g_exception_record;

void log_exception(CONTEXT *ctx, EXCEPTION_RECORD *rec,
    uintptr_t *return_addresses, uint32_t count)
{
    g_exception_return_address_count = count;
    memcpy(g_exception_return_addresses,
        return_addresses, count * sizeof(uintptr_t));
    memcpy(&g_exception_context, ctx, sizeof(CONTEXT));
    memcpy(&g_exception_record, rec, sizeof(EXCEPTION_RECORD));
    g_log_exception = 1;
}

static void _log_exception_perform()
{
    char buf[128]; bson b, s, e; CONTEXT *ctx = &g_exception_context;
    static int exception_count;

    g_log_exception = 0;

    bson_init(&b);
    bson_init(&s);
    bson_init(&e);

    if(exception_count++ == EXCEPTION_MAXCOUNT) {
        sprintf(buf, "Encountered %d exceptions, quitting.", exception_count);
        log_anomaly("exception", 1, NULL, buf);
        ExitProcess(1);
    }

#if __x86_64__
    static const char *regnames[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        NULL,
    };

    uintptr_t regvalues[] = {
        ctx->Rax, ctx->Rcx, ctx->Rdx, ctx->Rbx,
        ctx->Rsp, ctx->Rbp, ctx->Rsi, ctx->Rdi,
        ctx->R8,  ctx->R9,  ctx->R10, ctx->R11,
        ctx->R12, ctx->R13, ctx->R14, ctx->R15,
    };
#else
    static const char *regnames[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        NULL,
    };

    uintptr_t regvalues[] = {
        ctx->Eax, ctx->Ecx, ctx->Edx, ctx->Ebx,
        ctx->Esp, ctx->Ebp, ctx->Esi, ctx->Edi,
    };
#endif

    for (uint32_t idx = 0; regnames[idx] != NULL; idx++) {
        bson_append_long(&b, regnames[idx], regvalues[idx]);
    }

    char sym[512], number[20];

    const uint8_t *exception_address = (const uint8_t *)
        g_exception_record.ExceptionAddress;

    sprintf(buf, "0x%p", exception_address);
    bson_append_string(&e, "address", buf);

    char insn[DISASM_BUFSIZ];
    if(disasm(exception_address, insn) == 0) {
        bson_append_string(&e, "instruction", insn);
    }

    symbol(exception_address, sym, sizeof(sym));
    bson_append_string(&e, "symbol", sym);

    sprintf(buf, "0x%08x", (uint32_t) g_exception_record.ExceptionCode);
    bson_append_string(&e, "exception_code", buf);

    for (uint32_t idx = 0; idx < g_exception_return_address_count; idx++) {
        if(g_exception_return_addresses[idx] == 0) break;

        ultostr(idx, number);

        symbol((const uint8_t *) g_exception_return_addresses[idx],
            sym, sizeof(sym)-32);

        if(sym[0] != 0) {
            strcat(sym, " @ ");
        }

        sprintf(sym + strlen(sym), "0x%p",
            (void *) g_exception_return_addresses[idx]);
        bson_append_string(&s, number, sym);
    }

    bson_finish(&e);
    bson_finish(&s);
    bson_finish(&b);

    log_api(SIG___exception__, 1, 0, 0, &e, &b, &s);

    bson_destroy(&e);
    bson_destroy(&s);
    bson_destroy(&b);
}

static void *_bson_malloc(size_t length)
{
    return mem_alloc(length);
}

static void *_bson_realloc(void *ptr, size_t length)
{
    return mem_realloc(ptr, length);
}

static void _bson_free(void *ptr)
{
    mem_free(ptr);
}

void log_init(uint32_t ip, uint16_t port)
{
    InitializeCriticalSection(&g_mutex);

    bson_set_heap_stuff(&_bson_malloc, &_bson_realloc, &_bson_free);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Might be the case when debugging manually, but should never happen
    // during an actual analysis.
    if(ip == 0 || port == 0) {
        pipe("CRITICAL:No connection information found, logging to file!");
        g_sock = INVALID_SOCKET;
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
        g_sock = INVALID_SOCKET;
        return;
    }

    log_raw("BSON\n", 5);
    log_new_process();
}
