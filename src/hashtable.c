/*
 * Copyright © 2009 Intel Corporation
 * Copyright © 1988-2004 Keith Packard and Bart Massey.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Except as contained in this notice, the names of the authors
 * or their institutions shall not be used in advertising or
 * otherwise to promote the sale, use or other dealings in this
 * Software without prior written authorization from the
 * authors.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *    Keith Packard <keithp@keithp.com>
 * Integration in r2 core api:
 *    pancake <nopcode.org>
 * Normalized and extended:
 *    Jurriaan Bremer <jurriaanbremer@gmail.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "hashtable.h"
#include "memory.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

/*
 * From Knuth -- a good choice for hash/rehash values is p, p-2 where
 * p and p-2 are both prime.  These tables are sized to have an extra 10%
 * free to avoid exponential performance degradation as the hash table fills
 */

static const struct {
   uint32_t max_entries;
   uint32_t size;
   uint32_t rehash;
} hash_sizes[] = {
    { 2,            5,          3         },
    { 4,            7,          5         },
    { 8,            13,         11        },
    { 16,           19,         17        },
    { 32,           43,         41        },
    { 64,           73,         71        },
    { 128,          151,        149       },
    { 256,          283,        281       },
    { 512,          571,        569       },
    { 1024,         1153,       1151      },
    { 2048,         2269,       2267      },
    { 4096,         4519,       4517      },
    { 8192,         9013,       9011      },
    { 16384,        18043,      18041     },
    { 32768,        36109,      36107     },
    { 65536,        72091,      72089     },
    { 131072,       144409,     144407    },
    { 262144,       288361,     288359    },
    { 524288,       576883,     576881    },
    { 1048576,      1153459,    1153457   },
    { 2097152,      2307163,    2307161   },
    { 4194304,      4613893,    4613891   },
    { 8388608,      9227641,    9227639   },
    { 16777216,     18455029,   18455027  },
    { 33554432,     36911011,   36911009  },
    { 67108864,     73819861,   73819859  },
    { 134217728,    147639589,  147639587 },
    { 268435456,    295279081,  295279079 },
    { 536870912,    590559793,  590559791 },
    { 1073741824,   1181116273, 1181116271},
    { 2147483648,   2362232233, 2362232231},
};

#define entry_is_free(x) (x == NULL || x->length == 0)
#define entry_is_deleted(x) (x->length == 0)
#define entry_is_present(x) (x->length != 0)

/**
 * Finds a hash table entry with the given key and hash of that key.
 *
 * Returns NULL if no entry is found.  Note that the data pointer may be
 * modified by the user.
 */
static ht_entry_t* hashtable_search(const ht_t *ht, uint64_t hash)
{
    uint64_t double_hash, hash_address;
    if(ht == NULL) {
        return NULL;
    }

    uint32_t element_size = sizeof(*ht->table) + ht->data_length;
    hash_address = hash % ht->size;
    do {
        ht_entry_t *entry = (ht_entry_t *)(
            (char *) ht->table + hash_address * element_size);
        if(entry_is_free(entry)) {
            return NULL;
        }
        if(entry_is_present(entry) && entry->hash == hash) {
            return entry;
        }
        double_hash = hash % ht->rehash;
        if(double_hash == 0) {
            double_hash = 1;
        }
        hash_address = (hash_address + double_hash) % ht->size;
    } while (hash_address != hash % ht->size);
    return NULL;
}

static void hashtable_rehash(ht_t *ht, unsigned int new_size_index)
{
    ht_t old_ht = *ht;
    if(new_size_index >= ARRAY_SIZE(hash_sizes)) return;

    // XXX: This code is redupped! fuck't
    ht->table = (ht_entry_t *) mem_alloc(hash_sizes[new_size_index].size *
        (sizeof(*ht->table) + ht->data_length));
    if(ht->table == NULL) {
        return;
    }

    ht->data_length = old_ht.data_length;
    ht->size_index = new_size_index;
    ht->size = hash_sizes[ht->size_index].size;
    ht->rehash = hash_sizes[ht->size_index].rehash;
    ht->max_entries = hash_sizes[ht->size_index].max_entries;
    ht->entries = 0;
    ht->deleted_entries = 0;

    uint32_t element_size = sizeof(*ht->table) + ht->data_length;
    for (uint32_t idx = 0; idx < old_ht.size; idx++) {
        ht_entry_t *e = (ht_entry_t *)(
            (char *) old_ht.table + idx * element_size);
        if(entry_is_present(e)) {
            ht_insert2(ht, e->hash, e->data, e->length);
        }
    }
    mem_free(old_ht.table);
}

void ht_init(ht_t *ht, uint32_t data_length)
{
    ht->data_length = data_length != 0 ? data_length : sizeof(void *);
    // TODO: use slices here
    ht->size = hash_sizes[0].size;
    ht->table = (ht_entry_t *) mem_alloc(ht->size *
        (sizeof(*ht->table) + ht->data_length));
    if(ht->table == NULL) {
        return;
    }
    ht->size_index = 0;
    ht->entries = 0;
    ht->deleted_entries = 0;
    ht->rehash = hash_sizes[ht->size_index].rehash;
    ht->max_entries = hash_sizes[ht->size_index].max_entries;
    return;
}

void ht_free(ht_t *ht)
{
    if(ht != NULL) {
        mem_free(ht->table);
    }
}

int ht_next_key(const ht_t *ht, uint32_t *index, uint64_t *hash)
{
    uint32_t element_size = sizeof(*ht->table) + ht->data_length;

    for (uint32_t idx = *index; idx < ht->size; idx++) {
        ht_entry_t *e = (ht_entry_t *)(
            (char *) ht->table + idx * element_size);
        if(entry_is_present(e)) {
            *index = idx + 1;
            *hash = e->hash;
            return 0;
        }
    }
    return -1;
}

void *ht_lookup(const ht_t *ht, uint64_t hash, uint32_t *length)
{
    ht_entry_t *entry = hashtable_search(ht, hash);
    if(entry != NULL) {
        if(length != NULL) {
            *length = entry->length;
        }
        return entry->data;
    }
    return NULL;
}

int ht_contains(const ht_t *ht, uint64_t hash)
{
    ht_entry_t *entry = hashtable_search(ht, hash);
    return entry != NULL && entry->length != 0;
}

/**
 * Inserts the data with the given hash into the table.
 *
 * Note that insertion may rearrange the table on a resize or rehash,
 * so previously found hash_entries are no longer valid after this function.
 */
int ht_insert2(ht_t *ht, uint64_t hash, void *data, uint32_t length)
{
    uint64_t hash_address;

    if(length == 0 || length > ht->data_length) {
        return -1;
    }

    if(ht->entries >= ht->max_entries) {
        hashtable_rehash(ht, ht->size_index + 1);
    }
    else if(ht->deleted_entries + ht->entries >= ht->max_entries) {
        hashtable_rehash(ht, ht->size_index);
    }

    uint32_t element_size = sizeof(*ht->table) + ht->data_length;

    hash_address = hash % ht->size;
    do {
        ht_entry_t *entry = (ht_entry_t *)(
            (char *) ht->table + hash_address * element_size);

        if(!entry_is_present(entry)) {
            if(entry_is_deleted(entry)) {
                ht->deleted_entries--;
            }
            entry->hash = hash;
            entry->length = length;
            memcpy(entry->data, data, length);
            ht->entries++;
            return 0;
        }

        uint64_t double_hash = hash % ht->rehash;
        if(double_hash == 0) {
            double_hash = 1;
        }
        hash_address = (hash_address + double_hash) % ht->size;
    } while (hash_address != hash % ht->size);

    /* We could hit here if a required resize failed. An unchecked-malloc
     * application could ignore this result.
     */
    return -1;
}

int ht_insert(ht_t *ht, uint64_t hash, void *data)
{
    return ht_insert2(ht, hash, data, ht->data_length);
}

void ht_remove(ht_t *ht, uint64_t hash)
{
    ht_entry_t *entry = hashtable_search(ht, hash);
    if(entry != NULL && entry->length != 0) {
        entry->length = 0;
        ht->entries--;
        ht->deleted_entries++;
    }
}

uint64_t hash_str(const void *_s)
{
    const uint8_t *s = (const uint8_t *) _s;
    uint64_t ret = 0;
    while (*s != 0) {
        ret ^= (ret << 7) | *s++;
    }
    return ret;
}

uint64_t hash_mem(const void *_s, uint32_t length)
{
    const uint8_t *s = (const uint8_t *) _s;
    uint64_t ret = 0;
    while (length-- != 0) {
        ret ^= (ret << 7) | *s++;
    }
    return ret;
}
