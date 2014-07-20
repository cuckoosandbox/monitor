#ifndef MONITOR_SLIST_H
#define MONITOR_SLIST_H

#include <stdint.h>

typedef struct _slist_t {
    uint32_t index;
    uint32_t length;
    uint32_t *value;
} slist_t;

void slist_init(slist_t *s, uint32_t length);
void slist_push(slist_t *s, uint32_t value);
uint32_t slist_pop(slist_t *s);

#endif
