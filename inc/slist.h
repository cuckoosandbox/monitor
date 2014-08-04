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
