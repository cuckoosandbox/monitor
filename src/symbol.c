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
#include <windows.h>

static const uint8_t *_module_from_address(const uint8_t *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi) &&
            mbi.State != MEM_FREE) {
        addr = (const uint8_t *)((uintptr_t) addr & ~0xfff);
        while (*addr != 'M' || addr[1] != 'Z') {
            addr -= 0x1000;
        }
        return addr;
    }
    return NULL;
}

int symbol(const uint8_t *addr, char *sym, uint32_t length)
{
    int len; *sym = 0;

    const uint8_t *mod = _module_from_address(addr);
    if(mod == NULL) return -1;

    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) mod;
    IMAGE_NT_HEADERS *image_nt_headers =
        (IMAGE_NT_HEADERS *)(mod + image_dos_header->e_lfanew);

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

    uint32_t *function_addresses = (uint32_t *)(
        mod + export_directory->AddressOfFunctions);

    uint32_t *names_addresses = (uint32_t *)(
        mod + export_directory->AddressOfNames);

    uint16_t *ordinals = (uint16_t *)(
        mod + export_directory->AddressOfNameOrdinals);

    int32_t lower = -1, higher = -1;

    for (uint32_t idx = 0; idx < export_directory->NumberOfNames; idx++) {
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
            addr - mod - function_addresses[ordinals[lower]]);
        sym += len, length -= len;
    }
    if(higher != -1) {
        if(lower != -1) {
            len = snprintf(sym, length, " / ");
            sym += len, length -= len;
        }
        snprintf(sym, length, "%s-0x%x",
            (const char *) mod + names_addresses[higher],
            mod + function_addresses[ordinals[higher]] - addr);
    }
    return 0;
}
