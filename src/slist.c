// Simple List
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "slist.h"

void slist_init(slist_t *s, uint32_t length)
{
    s->index = 0;
    s->length = length;
    s->value = (uint32_t *) malloc(length * sizeof(uint32_t));
}

static void _slist_ensure(slist_t *s)
{
    if(s->index == s->length) {
        s->length *= 2;
        s->value = (uint32_t *) realloc(s->value,
            s->length * sizeof(uint32_t));

        memset(&s->value[s->index], 0xcc,
            s->index * sizeof(uint32_t));
    }
}


void slist_push(slist_t *s, uint32_t value)
{
    _slist_ensure(s);
    s->value[s->index++] = value;
}

uint32_t slist_pop(slist_t *s)
{
    if(s->index == 0) return 0;
    return s->value[--s->index];
}
