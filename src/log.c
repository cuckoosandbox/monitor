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
#include <windows.h>
#include "bson.h"
#include "hooking.h"
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
static uint32_t g_starttick;
static uint8_t *g_api_init;

static wchar_t g_log_pipename[MAX_PATH];
static HANDLE g_log_handle;

#if DEBUG
static wchar_t g_debug_filepath[MAX_PATH];
static HANDLE g_debug_handle;
#endif

static void log_raw(const char *buf, size_t length);

static int open_handles()
{
    do {
        // TODO Use NtCreateFile instead of CreateFileW.
        g_log_handle = CreateFileW(g_log_pipename, GENERIC_WRITE,
            FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH, NULL);

        sleep(50);
    } while (g_log_handle == INVALID_HANDLE_VALUE);

    // The process identifier.
    uint32_t process_identifier = get_current_process_id();
    log_raw((const char *) &process_identifier, sizeof(process_identifier));

#if DEBUG
    g_debug_handle = CreateFileW(g_debug_filepath,
        GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif
    return 0;
}

static void log_raw(const char *buf, size_t length)
{
    EnterCriticalSection(&g_mutex);

    while (length != 0) {
        uint32_t written = 0; uint32_t status;

        status = write_file(g_log_handle, buf, length, &written);
        if(NT_SUCCESS(status) == FALSE) {
            // It is possible that malware closes our pipe handle. In that
            // case we'll get an invalid handle error. Let's just open a new
            // pipe handle.
            if(status == STATUS_INVALID_HANDLE) {
                if(open_handles() < 0) {
                    break;
                }
            }
            else {
                pipe("CRITICAL:Handle case where the log handle is closed "
                    "(last error 0x%x).", status);
                break;
            }
        }

        length -= written, buf += written;
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

static void log_intptr(bson *b, const char *idx, intptr_t value)
{
#if __x86_64__
    bson_append_long(b, idx, value);
#else
    bson_append_int(b, idx, value);
#endif
}

static void log_string(bson *b, const char *idx, const char *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    int ret, utf8len;

    if(range_is_readable(str, length) != 0) {
        char *utf8s = utf8_string(str, length);
        utf8len = *(int *) utf8s;
        ret = bson_append_binary(b, idx, BSON_BIN_BINARY, utf8s+4, utf8len);
        if(ret == BSON_ERROR) {
            pipe("CRITICAL:Error creating bson string, error, %x utf8len %d.",
                b->err, utf8len);
        }
        mem_free(utf8s);
    }
    else {
        bson_append_binary(b, idx, BSON_BIN_BINARY, "<INVALID POINTER>", 17);
    }
}

void log_wstring(bson *b, const char *idx, const wchar_t *str, int length)
{
    if(str == NULL) {
        bson_append_string_n(b, idx, "", 0);
        return;
    }

    if(range_is_readable(str, length) != 0) {
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
    else {
        bson_append_binary(b, idx, BSON_BIN_BINARY, "<INVALID POINTER>", 17);
    }
}

static void log_argv(bson *b, const char *idx, int argc, const char **argv)
{
    bson_append_start_array(b, idx);
    char index[5];

    for (int i = 0; i < argc; i++) {
        ultostr(i, index, 10);
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
        ultostr(i, index, 10);
        log_wstring(b, index, argv[i], -1);
    }

    bson_append_finish_array(b);
}

static void log_buffer(bson *b, const char *idx,
    const uint8_t *buf, uintptr_t length)
{
    uintptr_t trunclength = length < BUFFER_LOG_MAX ? length : BUFFER_LOG_MAX;

    if(buf == NULL) {
        trunclength = 0;
    }

    if(range_is_readable(buf, length) != 0) {
        bson_append_binary(b, idx, BSON_BIN_BINARY,
            (const char *) buf, trunclength);
    }
    else {
        bson_append_binary(b, idx, BSON_BIN_BINARY, "<INVALID POINTER>", 17);
    }
}

static void log_buffer_notrunc(const uint8_t *buf, uintptr_t length)
{
    if(buf == NULL || length == 0) {
        return;
    }

    bson b;
    bson_init(&b);
    bson_append_string(&b, "type", "buffer");

    if(range_is_readable(buf, length) != 0) {
        bson_append_binary(&b, "buffer", BSON_BIN_BINARY,
            (const char *) buf, length);

        char checksum[64];
        sha1(buf, length, checksum);
        bson_append_string(&b, "checksum", checksum);
    }
    else {
        bson_append_string(&b, "buffer", "<INVALID POINTER>");
        bson_append_string(&b, "checksum", "???");
    }

    bson_finish(&b);
    log_raw(bson_data(&b), bson_size(&b));
    bson_destroy(&b);
}

void log_explain(uint32_t index)
{
    bson b; char argidx[4];

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_string(&b, "name", sig_apiname(index));
    bson_append_string(&b, "type", "info");
    bson_append_string(&b, "category", sig_category(index));

    bson_append_start_array(&b, "args");
    bson_append_string(&b, "0", "is_success");
    bson_append_string(&b, "1", "retval");

    const char *fmt = sig_paramtypes(index);

    for (uint32_t argnum = 2; *fmt != 0; argnum++, fmt++) {
        ultostr(argnum, argidx, 10);

        // Ignore buffers, they are sent over separately.
        if(*fmt == '!') {
            argnum--;
            fmt++;
            continue;
        }

        const char *argname = sig_param_name(index, argnum-2);

        // On certain formats, we need to tell cuckoo about them for
        // nicer display / matching.
        if(*fmt == 'p' || *fmt == 'P' || *fmt == 'x') {
            bson_append_start_array(&b, argidx);
            bson_append_string(&b, "0", argname);

            if(*fmt == 'p' || *fmt == 'P') {
                bson_append_string(&b, "1", "p");
            }
            else if(*fmt == 'x') {
                bson_append_string(&b, "1", "x");
            }
            bson_append_finish_array(&b);
        }
        else {
            bson_append_string(&b, argidx, argname);
        }
    }

    bson_append_finish_array(&b);
    bson_append_start_object(&b, "flags_value");

    for (uint32_t idx = 0; sig_flag_name(index, idx) != NULL; idx++) {
        const flag_repr_t *f = flag_value(sig_flag_value(index, idx));
        bson_append_start_array(&b, sig_flag_name(index, idx));

        for (uint32_t idx2 = 0; f->repr != NULL; idx2++, f++) {
            ultostr(idx, argidx, 10);
            bson_append_start_array(&b, argidx);
            bson_append_int(&b, "0", f->value);
            bson_append_string(&b, "1", f->repr);
            bson_append_finish_array(&b);
        }

        bson_append_finish_array(&b);
    }

    bson_append_finish_object(&b);
    bson_append_start_object(&b, "flags_bitmask");

    for (uint32_t idx = 0; sig_flag_name(index, idx) != NULL; idx++) {
        const flag_repr_t *f = flag_bitmask(sig_flag_value(index, idx));
        bson_append_start_array(&b, sig_flag_name(index, idx));

        for (uint32_t idx2 = 0; f->repr != NULL; idx2++, f++) {
            ultostr(idx, argidx, 10);
            bson_append_start_array(&b, argidx);
            bson_append_int(&b, "0", f->value);
            bson_append_string(&b, "1", f->repr);
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

    count = stacktrace(NULL, addrs, RETADDRCNT);

    for (uint32_t idx = 4; idx < count; idx++) {
        ultostr(idx-4, number, 10);

        symbol((const uint8_t *) addrs[idx], sym, sizeof(sym)-32);
        if(sym[0] != 0) {
            our_snprintf(sym + our_strlen(sym),
                sizeof(sym) - our_strlen(sym), " @ ");
        }

        our_snprintf(sym + our_strlen(sym), sizeof(sym) - our_strlen(sym),
            "%p", (const uint8_t *) addrs[idx]);
        bson_append_string(b, number, sym);
    }

    bson_append_finish_array(b);
}

#endif

void log_api(uint32_t index, int is_success, uintptr_t return_value,
    uint64_t hash, last_error_t *lasterr, ...)
{
    va_list args; char idx[4];
    va_start(args, lasterr);

    EnterCriticalSection(&g_mutex);

    if(g_api_init[index] == 0) {
        log_explain(index);
        g_api_init[index] = 1;
    }

    LeaveCriticalSection(&g_mutex);

    bson b;

    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_int(&b, "I", index);
    bson_append_int(&b, "T", get_current_thread_id());
    bson_append_int(&b, "t", get_tick_count() - g_starttick);
    bson_append_long(&b, "h", hash);

    // If failure has been determined, then log the last error as well.
    if(is_success == 0) {
        bson_append_int(&b, "e", lasterr->lasterror);
        bson_append_int(&b, "E", lasterr->nt_status);
    }

#if DEBUG
    _log_stacktrace(&b);
#endif

    bson_append_start_array(&b, "args");
    bson_append_int(&b, "0", is_success);
    bson_append_long(&b, "1", return_value);

    int argnum = 2, override = 0;

    for (const char *fmt = sig_paramtypes(index); *fmt != 0; fmt++) {
        ultostr(argnum++, idx, 10);

        // Limitation override. Instead of displaying this right away in the
        // report we turn it into a buffer (much like the dropped files).
        if(*fmt == '!') {
            override = 1;
            argnum--;
            fmt++;
        }

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
            uintptr_t len = va_arg(args, uintptr_t);
            const uint8_t *s = va_arg(args, const uint8_t *);
            if(override == 0) {
                log_buffer(&b, idx, s, len);
            }
            else {
                log_buffer_notrunc(s, len);
            }
        }
        else if(*fmt == 'B') {
            uintptr_t *len = va_arg(args, uintptr_t *);
            const uint8_t *s = va_arg(args, const uint8_t *);
            if(override == 0) {
                log_buffer(&b, idx, s, len == NULL ? 0 : *len);
            }
            else {
                log_buffer_notrunc(s, len == NULL ? 0 : *len);
            }
        }
        else if(*fmt == 'i' || *fmt == 'x') {
            int value = va_arg(args, int);
            log_int32(&b, idx, value);
        }
        else if(*fmt == 'I') {
            int *value = va_arg(args, int *);
            log_int32(&b, idx, value != NULL ? *value : 0);
        }
        else if(*fmt == 'l' || *fmt == 'p') {
            uintptr_t value = va_arg(args, uintptr_t);
            log_intptr(&b, idx, value);
        }
        else if(*fmt == 'L' || *fmt == 'P') {
            uintptr_t *ptr = va_arg(args, uintptr_t *);
            log_intptr(&b, idx, ptr != NULL ? *ptr : 0);
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
                uint32_t value = 0;
                if(data != NULL) {
                    value = *(uint32_t *) data;
                }
                log_int32(&b, idx, value);
            }
            else if(*type == REG_DWORD_BIG_ENDIAN) {
                uint32_t value = 0;
                if(data != NULL) {
                    value = *(uint32_t *) data;
                }
                log_int32(&b, idx, our_htonl(value));
            }
            else if(*type == REG_EXPAND_SZ || *type == REG_SZ ||
                    *type == REG_MULTI_SZ) {
                if(*fmt == 'r') {
                    uint32_t length = *size;
                    // Strings tend to be zero-terminated twice, so check for
                    // that and if that's the case, then ignore the trailing
                    // nullbyte.
                    if(data != NULL &&
                            our_strlen((const char *) data) == length - 1) {
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
                uint64_t value = 0;
                if(data != NULL) {
                    value = *(uint64_t *) data;
                }
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
            char buf[64];
            REFCLSID rclsid = va_arg(args, REFCLSID);
            clsid_to_string(rclsid, buf);
            log_string(&b, idx, buf, -1);
        }
        else {
            char buf[2] = {*fmt, 0};
            pipe("CRITICAL:Invalid format specifier: %z", buf);
        }

        override = 0;
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

    wchar_t *command_line = GetCommandLineW();

    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

#if __x86_64__
    int is_64bit = 1;
#else
    int is_64bit = 0;
#endif

    log_api(sig_index_process(), 1, 0, 0, NULL, st.dwLowDateTime,
        st.dwHighDateTime, get_current_process_id(),
        parent_process_identifier(), module_path, command_line, is_64bit);

    free_unicode_buffer(module_path);
}

void log_anomaly(const char *subcategory,
    const char *funcname, const char *msg)
{
    log_api(sig_index_anomaly(), 1, 0, 0, NULL,
        get_current_thread_id(), subcategory, funcname, msg);
}

void log_exception(CONTEXT *ctx, EXCEPTION_RECORD *rec,
    uintptr_t *return_addresses, uint32_t count)
{
    char buf[128]; bson b, s, e;
    static int exception_count;

    bson_init(&b);
    bson_init(&s);
    bson_init(&e);

    if(exception_count++ == EXCEPTION_MAXCOUNT) {
        our_snprintf(buf, sizeof(buf), "Encountered %d exceptions, quitting.",
            exception_count);
        log_anomaly("exception", NULL, buf);
        ExitProcess(1);
    }

#if __x86_64__
    static const char *regnames[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        NULL,
    };

    uintptr_t regvalues[16] = {};

    if(ctx != NULL) {
        uintptr_t registers[] = {
            ctx->Rax, ctx->Rcx, ctx->Rdx, ctx->Rbx,
            ctx->Rsp, ctx->Rbp, ctx->Rsi, ctx->Rdi,
            ctx->R8,  ctx->R9,  ctx->R10, ctx->R11,
            ctx->R12, ctx->R13, ctx->R14, ctx->R15,
        };
        memcpy(regvalues, registers, sizeof(registers));
    }
#else
    static const char *regnames[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        NULL,
    };

    uintptr_t regvalues[8] = {};

    if(ctx != NULL) {
        uintptr_t registers[] = {
            ctx->Eax, ctx->Ecx, ctx->Edx, ctx->Ebx,
            ctx->Esp, ctx->Ebp, ctx->Esi, ctx->Edi,
        };
        memcpy(regvalues, registers, sizeof(registers));
    }
#endif

    for (uint32_t idx = 0; regnames[idx] != NULL; idx++) {
        bson_append_long(&b, regnames[idx], regvalues[idx]);
    }

    char sym[512], number[20];

    const uint8_t *exception_address = NULL;
    if(rec != NULL) {
        exception_address = (const uint8_t *) rec->ExceptionAddress;
    }

    our_snprintf(buf, sizeof(buf), "%p", exception_address);
    bson_append_string(&e, "address", buf);

    char insn[DISASM_BUFSIZ];
    if(range_is_readable(exception_address, 16) != 0 &&
            disasm(exception_address, insn) == 0) {
        bson_append_string(&e, "instruction", insn);
    }

    symbol(exception_address, sym, sizeof(sym));
    bson_append_string(&e, "symbol", sym);

    our_snprintf(buf, sizeof(buf), "%p",
        rec != NULL ? (uintptr_t) rec->ExceptionCode : 0);
    bson_append_string(&e, "exception_code", buf);

    for (uint32_t idx = 0; idx < count; idx++) {
        if(return_addresses[idx] == 0) break;

        ultostr(idx, number, 10);

        symbol((const uint8_t *) return_addresses[idx], sym, sizeof(sym)-32);

        if(sym[0] != 0) {
            strcat(sym, " @ ");
        }

        our_snprintf(sym + our_strlen(sym), sizeof(sym) - our_strlen(sym),
            "%p", (void *) return_addresses[idx]);
        bson_append_string(&s, number, sym);
    }

    bson_finish(&e);
    bson_finish(&s);
    bson_finish(&b);

    log_api(sig_index_exception(), 1, 0, 0, NULL, &e, &b, &s);

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

#if DEBUG

void log_debug(const char *fmt, ...)
{
    EnterCriticalSection(&g_mutex);

    static char message[0x1000]; int length; va_list args;

    va_start(args, fmt);
    length = our_vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    write_file(g_debug_handle, message, length, NULL);

    LeaveCriticalSection(&g_mutex);
}

#endif

void WINAPI log_missing_hook(const char *funcname)
{
    // if(hook_in_monitor() == 0) {
        log_api(sig_index_missing(), 1, 0, 0, NULL, funcname);
    // }
}

void log_init(const char *pipe_name)
{
    InitializeCriticalSection(&g_mutex);

    bson_set_heap_stuff(&_bson_malloc, &_bson_realloc, &_bson_free);
    g_api_init = virtual_alloc_rw(NULL, sig_count() * sizeof(uint8_t));

#if DEBUG
    char filepath[MAX_PATH];
    our_snprintf(filepath, MAX_PATH, "C:\\monitor-debug-%d.txt",
        GetCurrentProcessId());
    pipe("FILE_NEW:%z", filepath);
    wcsncpyA(g_debug_filepath, filepath, MAX_PATH);
#endif

    wcsncpyA(g_log_pipename, pipe_name, MAX_PATH);
    open_handles();

    log_raw("BSON\n", 5);
    log_new_process();
}
