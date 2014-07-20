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
