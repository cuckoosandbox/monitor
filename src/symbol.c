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
#include <windows.h>
#include "misc.h"
#include "native.h"
#include "pipe.h"
#include "symbol.h"

static const uint8_t *g_monitor_base_address;
static uint32_t *g_monitor_function_addresses;
static uint32_t *g_monitor_names_addresses;
static uint16_t *g_monitor_ordinals;
static uint32_t g_monitor_number_of_names;
static uint32_t g_monitor_image_size;

const uint8_t *module_from_address(const uint8_t *addr)
{
    MEMORY_BASIC_INFORMATION_CROSS mbi;

    if(virtual_query(addr, &mbi) == FALSE ||
            range_is_readable((const uint8_t *) mbi.AllocationBase, 2) == 0) {
        return NULL;
    }

    addr = (const uint8_t *) mbi.AllocationBase;

    // We're looking for either an MZ header or the image base address
    // of our monitor.
    if(our_memcmp(addr, "MZ", 2) == 0 || addr == g_monitor_base_address) {
        return addr;
    }

    return NULL;
}

uint32_t module_image_size(const uint8_t *addr)
{
    if(addr == g_monitor_base_address) {
        return g_monitor_image_size;
    }

    if(addr == NULL) {
        return 0;
    }

    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) addr;
    if(image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    IMAGE_NT_HEADERS_CROSS *image_nt_headers =
        (IMAGE_NT_HEADERS_CROSS *)(addr + image_dos_header->e_lfanew);
    if(image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return image_nt_headers->OptionalHeader.SizeOfImage;
}

static int _eat_pointers_for_module(const uint8_t *mod,
    uint32_t **function_addresses, uint32_t **names_addresses,
    uint16_t **ordinals, uint32_t *number_of_names)
{
    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) mod;
    IMAGE_NT_HEADERS_CROSS *image_nt_headers =
        (IMAGE_NT_HEADERS_CROSS *)(mod + image_dos_header->e_lfanew);

    // Check whether this module is the Monitor DLL. As the monitor destroys
    // its own PE header we cache the related pointers. Fetch them now.
    if(mod == g_monitor_base_address) {
        *function_addresses = g_monitor_function_addresses;
        *names_addresses = g_monitor_names_addresses;
        *ordinals = g_monitor_ordinals;
        *number_of_names = g_monitor_number_of_names;
        return 0;
    }

    IMAGE_DATA_DIRECTORY *data_directories =
        image_nt_headers->OptionalHeader.DataDirectory;
    if(image_nt_headers->OptionalHeader.NumberOfRvaAndSizes <
            IMAGE_DIRECTORY_ENTRY_EXPORT + 1) {
        return -1;
    }

    IMAGE_DATA_DIRECTORY *export_data_directory =
        &data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(export_data_directory->VirtualAddress == 0 ||
            export_data_directory->Size == 0) {
        return -1;
    }

    IMAGE_EXPORT_DIRECTORY *export_directory = (IMAGE_EXPORT_DIRECTORY *)(
        mod + export_data_directory->VirtualAddress);

    // Due to corrupted PE files or incorrect loading of the PE file by us
    // the export directory may point to invalid memory. If so, don't crash.
    if(range_is_readable(export_directory,
            sizeof(IMAGE_EXPORT_DIRECTORY)) == 0) {
        return -1;
    }

    *number_of_names = export_directory->NumberOfNames;
    *function_addresses = (uint32_t *)(
        mod + export_directory->AddressOfFunctions);
    *names_addresses = (uint32_t *)(mod + export_directory->AddressOfNames);
    *ordinals = (uint16_t *)(mod + export_directory->AddressOfNameOrdinals);
    return 0;
}

void symbol_init(HMODULE monitor_address)
{
    _eat_pointers_for_module((const uint8_t *) monitor_address,
        &g_monitor_function_addresses, &g_monitor_names_addresses,
        &g_monitor_ordinals, &g_monitor_number_of_names);

    g_monitor_image_size =
        module_image_size((const uint8_t *) monitor_address);

    // It's important to resolve the base address at the end of this function
    // because otherwise the earlier function calls will return NULL pointers
    // as the base address has already been initialized, but the fetched
    // values have not.
    g_monitor_base_address = (const uint8_t *) monitor_address;
}

int symbol_enumerate_module(HMODULE module_handle,
    symbol_callback_t callback, void *context)
{
    uint32_t *function_addresses, *names_addresses, number_of_names;
    uint16_t *ordinals;

    if(_eat_pointers_for_module((const uint8_t *) module_handle,
            &function_addresses, &names_addresses, &ordinals,
            &number_of_names) < 0) {
        return -1;
    }

    for (uint32_t idx = 0; idx < number_of_names; idx++) {
        const char *funcname =
            (const char *) module_handle + names_addresses[idx];

        uintptr_t address =
            (uintptr_t) module_handle + function_addresses[ordinals[idx]];

        callback(funcname, address, context);
    }

    return 0;
}

typedef struct _symbol_t {
    uintptr_t address;

    uintptr_t lower_address;
    uintptr_t higher_address;

    const char *lower_funcname;
    const char *higher_funcname;
} symbol_t;

static void _symbol_callback(
    const char *funcname, uintptr_t address, void *context)
{
    symbol_t *s = (symbol_t *) context;

    if(s->address > address && (s->lower_address == 0 ||
            address > s->lower_address)) {
        s->lower_address = address;
        s->lower_funcname = funcname;
    }

    if(s->address < address && (s->higher_address == 0 ||
            address < s->higher_address)) {
        s->higher_address = address;
        s->higher_funcname = funcname;
    }
}

int symbol(const uint8_t *addr, char *sym, uint32_t length)
{
    int len; *sym = 0;

    const uint8_t *mod = module_from_address(addr);
    if(mod == NULL) {
        return -1;
    }

    const wchar_t *module_name = get_module_file_name((HMODULE) mod);

    symbol_t s;

    s.address = (uintptr_t) addr;
    s.lower_address = s.higher_address = 0;
    s.lower_funcname = s.higher_funcname = NULL;

    symbol_enumerate_module((HMODULE) mod, &_symbol_callback, &s);

    if(s.lower_address != 0) {
        len = our_snprintf(sym, length, "%s+%p",
            s.lower_funcname, (uintptr_t) addr - s.lower_address);
        sym += len, length -= len;
    }

    if(s.higher_address != 0) {
        if(s.lower_address != 0) {
            *sym++ = ' ', length--;
        }
        len = our_snprintf(sym, length, "%s-%p",
            s.higher_funcname, s.higher_address - (uintptr_t) addr);
        sym += len, length -= len;
    }

    if(module_name != NULL) {
        if(s.lower_address != 0 || s.higher_address != 0) {
            *sym++ = ' ', length--;
        }

        while (length-- > 20 && *module_name != 0 && *module_name != '.') {
            *sym++ = tolower(*module_name++);
        }

        our_snprintf(sym, length, "+%p", addr - mod);
    }
    return 0;
}
