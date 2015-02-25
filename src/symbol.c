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
            page_is_readable((const uint8_t *) mbi.AllocationBase) == 0) {
        return NULL;
    }

    addr = (const uint8_t *) mbi.AllocationBase;

    // We're looking for either an MZ header or the image base address
    // of our monitor.
    if(memcmp(addr, "MZ", 2) == 0 || addr == g_monitor_base_address) {
        return addr;
    }

    return NULL;
}

uint32_t module_image_size(const uint8_t *addr)
{
    if(addr == g_monitor_base_address) {
        return g_monitor_image_size;
    }

    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) addr;
    if(image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    IMAGE_NT_HEADERS *image_nt_headers =
        (IMAGE_NT_HEADERS *)(addr + image_dos_header->e_lfanew);
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
    IMAGE_NT_HEADERS *image_nt_headers =
        (IMAGE_NT_HEADERS *)(mod + image_dos_header->e_lfanew);

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

    *number_of_names = export_directory->NumberOfNames;
    *function_addresses = (uint32_t *)(
        mod + export_directory->AddressOfFunctions);
    *names_addresses = (uint32_t *)(mod + export_directory->AddressOfNames);
    *ordinals = (uint16_t *)(mod + export_directory->AddressOfNameOrdinals);
    return 0;
}

void symbol_init(HMODULE module_handle)
{
    _eat_pointers_for_module((uint8_t *) module_handle,
        &g_monitor_function_addresses, &g_monitor_names_addresses,
        &g_monitor_ordinals, &g_monitor_number_of_names);

    g_monitor_image_size = module_image_size((const uint8_t *) module_handle);

    // It's important to resolve the base address at the end of this function
    // because otherwise the earlier function calls will return NULL pointers
    // as the base address has already been initialized, but the fetched
    // values have not.
    g_monitor_base_address = (const uint8_t *) module_handle;
}

int symbol(const uint8_t *addr, char *sym, uint32_t length)
{
    int len; *sym = 0;

    const uint8_t *mod = module_from_address(addr);
    if(mod == NULL) {
        pipe("DEBUG:Unable to find module for address 0x%x.", addr);
        return -1;
    }

    uint32_t *function_addresses, *names_addresses, number_of_names;
    uint16_t *ordinals;

    if(_eat_pointers_for_module(mod, &function_addresses, &names_addresses,
            &ordinals, &number_of_names) < 0) {
        return -1;
    }

    int32_t lower = -1, higher = -1;

    for (uint32_t idx = 0; idx < number_of_names; idx++) {
        const uint8_t *fnaddr = mod + function_addresses[ordinals[idx]];

        if(addr > fnaddr && (lower == -1 ||
                fnaddr > mod + function_addresses[ordinals[lower]])) {
            lower = idx;
        }
        if(addr < fnaddr && (higher == -1 ||
                fnaddr < mod + function_addresses[ordinals[higher]])) {
            higher = idx;
        }
    }

    if(lower != -1) {
        len = snprintf(sym, length, "%s+0x%x",
            (const char *) mod + names_addresses[lower],
            (uint32_t)(addr - mod - function_addresses[ordinals[lower]]));
        sym += len, length -= len;
    }
    if(higher != -1) {
        if(lower != -1) {
            len = snprintf(sym, length, " / ");
            sym += len, length -= len;
        }
        snprintf(sym, length, "%s-0x%x",
            (const char *) mod + names_addresses[higher],
            (uint32_t)(mod + function_addresses[ordinals[higher]] - addr));
    }
    return 0;
}
