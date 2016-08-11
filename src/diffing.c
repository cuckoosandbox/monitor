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
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "hooking.h"
#include "ignore.h"
#include "memory.h"
#include "misc.h"
#include "pipe.h"

typedef struct _module_t {
    uintptr_t base;
    uintptr_t end;
    uint64_t  hash;
} module_t;

#define MAX_MODULE_COUNT 256
#define HASH_INTERESTING 0
#define HASH_IGNORE 1
#define ENSURE_HASH_NOT_SPECIAL(value) \
    ((value) == HASH_INTERESTING || (value) == HASH_IGNORE ? \
        HASH_INTERESTING+2 : (value))

static uint32_t g_module_count;
static module_t g_modules[MAX_MODULE_COUNT];
static int g_diffing_enabled;

static dnq_t g_list;

static uint64_t _get_module_hash(HMODULE module_handle)
{
    wchar_t *module_path = get_unicode_buffer();
    wchar_t *full_path = get_unicode_buffer();

    GetModuleFileNameW(module_handle, module_path, MAX_PATH_W);
    uint32_t length = path_get_full_pathW(module_path, full_path);

    return hash_stringW(full_path, length);
}

static uint64_t _address_hash(uintptr_t addr)
{
    // TODO Use divide and conquer here as well.
    for (uint32_t idx = 0; idx < g_module_count; idx++) {
        if(addr >= g_modules[idx].base && addr < g_modules[idx].end) {
            uint64_t ret =
                g_modules[idx].hash ^ hash_uint64(addr - g_modules[idx].base);
            return ENSURE_HASH_NOT_SPECIAL(ret);
        }
    }

    // If we can't find the module hash then we have to create one.
    const uint8_t *module_address =
        module_from_address((const uint8_t *) addr);

    // If there's no module associated with this address then we
    // automatically tag this address as interesting.
    if(module_address == NULL) {
        return HASH_INTERESTING;
    }

    // What else to return?
    if(g_module_count == MAX_MODULE_COUNT) {
        pipe("CRITICAL:Exceeding the maximum amount of supported modules!");
        return HASH_INTERESTING;
    }

    // Add an entry for this module. TODO Spinlock around this code.
    g_modules[g_module_count].base = (uintptr_t) module_address;
    g_modules[g_module_count].end = (uintptr_t) module_address +
        module_image_size(module_address);
    g_modules[g_module_count++].hash =
        _get_module_hash((HMODULE) module_address);
    return _address_hash(addr);
}

static uint64_t _stacktrace_hash()
{
    uintptr_t addrs[RETADDRCNT], count = 0, hashcnt = 0; uint64_t hashes[64];

    count = stacktrace(NULL, addrs, RETADDRCNT);

    for (uint32_t idx = 0; idx < count; idx++) {
        uint64_t hash = _address_hash(addrs[idx]);
        if(hash == HASH_INTERESTING) {
            return HASH_INTERESTING;
        }

        hashes[hashcnt++] = hash;
    }

    uint64_t ret = hash_buffer(hashes, sizeof(uint64_t) * hashcnt);
    return ENSURE_HASH_NOT_SPECIAL(ret);
}

static uint64_t _parameter_hash(const char *fmt, va_list args)
{
    uint32_t value, hashcnt = 0; uintptr_t value2, *valueptr;
    uint64_t hashes[64]; HANDLE object_handle;

    while (*fmt != 0) {
        switch (*fmt++) {
        case 's':
            hashes[hashcnt++] = hash_string(va_arg(args, const char *), -1);
            break;

        case 'S':
            value = va_arg(args, uint32_t);
            hashes[hashcnt++] =
                hash_string(va_arg(args, const char *), value);
            break;

        case 'u':
            hashes[hashcnt++] =
                hash_stringW(va_arg(args, const wchar_t *), -1);
            break;

        case 'U':
            value = va_arg(args, uint32_t);
            hashes[hashcnt++] =
                hash_stringW(va_arg(args, const wchar_t *), value);
            break;

        case 'i':
            value = va_arg(args, uint32_t);
            hashes[hashcnt++] = hash_buffer(&value, sizeof(uint32_t));
            break;

        case 'p':
            value2 = va_arg(args, uintptr_t);
            hashes[hashcnt++] = hash_buffer(&value2, sizeof(uintptr_t));
            break;

        case 'I':
            valueptr = va_arg(args, uintptr_t *);
            if(valueptr != NULL) {
                hashes[hashcnt++] = hash_buffer(valueptr, sizeof(uint32_t));
            }
            break;

        case 'P':
            valueptr = va_arg(args, uintptr_t *);
            if(valueptr != NULL) {
                hashes[hashcnt++] = hash_buffer(valueptr, sizeof(uintptr_t));
            }
            break;

        case 'b':
            value = va_arg(args, uint32_t);
            hashes[hashcnt++] = hash_buffer(va_arg(args, void *), value);
            break;

        case 'h':
            object_handle = va_arg(args, HANDLE);
            if(is_ignored_object_handle(object_handle) != 0) {
                return HASH_IGNORE;
            }
            break;
        }
    }

    uint64_t ret = hash_buffer(hashes, sizeof(uint64_t) * hashcnt);
    return ENSURE_HASH_NOT_SPECIAL(ret);
}

void diffing_init(const char *path, int enable)
{
    FILE *fp = fopen(path, "rb");
    if(fp != NULL) {
        fseek(fp, 0, SEEK_END);
        uint32_t filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        uint64_t *list = (uint64_t *) VirtualAlloc(
            NULL, filesize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
        );
        if(list != NULL) {
            fread(list, filesize, 1, fp);

            dnq_init(
                &g_list, list, sizeof(uint64_t), filesize / sizeof(uint64_t)
            );
        }

        fclose(fp);
        DeleteFile(path);
    }

    g_diffing_enabled = enable;
}

uint64_t call_hash(const char *fmt, ...)
{
    // If no diffing list has been initialized and diffing has not been
    // explicitly enabled, then ignore all call_hash() calls.
    if(dnq_isempty(&g_list) != 0 && g_diffing_enabled == 0) {
        return HASH_INTERESTING;
    }

    va_list args;
    va_start(args, fmt);

    uint64_t hash1 = _stacktrace_hash();
    uint64_t hash2 = _parameter_hash(fmt, args);

    va_end(args);

    if(hash1 == HASH_IGNORE || hash2 == HASH_IGNORE) {
        return HASH_IGNORE;
    }

    if(hash1 == HASH_INTERESTING || hash2 == HASH_INTERESTING) {
        return HASH_INTERESTING;
    }

    return ENSURE_HASH_NOT_SPECIAL(hash1 ^ hash2);
}

int is_interesting_hash(uint64_t hash)
{
    if(hash == HASH_IGNORE) {
        return 0;
    }

    if(hash == HASH_INTERESTING) {
        return 1;
    }

    // No diffing list available - everything is interesting.
    if(dnq_isempty(&g_list) != 0) {
        return 1;
    }

    return dnq_has64(&g_list, hash);
}
