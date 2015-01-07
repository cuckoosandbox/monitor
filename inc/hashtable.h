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

#ifndef MONITOR_HASHTABLE_H
#define MONITOR_HASHTABLE_H

#include <stdint.h>

typedef struct _ht_entry_t {
    uint64_t hash;
    uint32_t length;
    uint8_t data[0];
} ht_entry_t;

typedef struct _ht_t {
    ht_entry_t *table;
    uint32_t data_length;
    uint32_t size_index;
    uint64_t size;
    uint64_t rehash;
    uint64_t max_entries;
    uint64_t entries;
    uint64_t deleted_entries;
} ht_t;

void ht_init(ht_t *ht, uint32_t data_length);
void ht_free(ht_t *ht);
int ht_next_key(const ht_t *ht, uint32_t *index, uint64_t *hash);
void *ht_lookup(const ht_t *ht, uint64_t hash, uint32_t *length);
int ht_contains(const ht_t *ht, uint64_t hash);
int ht_insert(ht_t *ht, uint64_t hash, void *data);
int ht_insert2(ht_t *ht, uint64_t hash, void *data, uint32_t length);
void ht_remove(ht_t *ht, uint64_t hash);

uint64_t hash_str(const void *s);
uint64_t hash_mem(const void *s, uint32_t length);

#endif
