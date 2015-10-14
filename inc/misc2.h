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

#ifndef MONITOR_MISC2_H
#define MONITOR_MISC2_H

#include <stdint.h>
#include <winsock2.h>
#include <security.h>

void wsabuf_get_buffer(uint32_t buffer_count, const WSABUF *buffers,
    uint8_t **ptr, uintptr_t *length);

void secbuf_get_buffer(uint32_t buffer_count, SecBuffer *buffers,
    uint8_t **ptr, uintptr_t *length);

#endif
