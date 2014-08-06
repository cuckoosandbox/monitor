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

// Simple List
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "slist.h"

void slist_init(slist_t *s, uintptr_t length)
{
    s->index = 0;
    s->length = length;
    s->value = (uintptr_t *) malloc(length * sizeof(uintptr_t));
}

static void _slist_ensure(slist_t *s)
{
    if(s->index == s->length) {
        s->length *= 2;
        s->value = (uintptr_t *) realloc(s->value,
            s->length * sizeof(uintptr_t));

        memset(&s->value[s->index], 0xcc,
            s->index * sizeof(uintptr_t));
    }
}


void slist_push(slist_t *s, uintptr_t value)
{
    _slist_ensure(s);
    s->value[s->index++] = value;
}

uintptr_t slist_pop(slist_t *s)
{
    if(s->index == 0) return 0;
    return s->value[--s->index];
}
