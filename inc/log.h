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

#ifndef MONITOR_LOG_H
#define MONITOR_LOG_H

#include <stdint.h>

void log_init(uint32_t ip, uint16_t port);
void log_free();

void log_explain();

void log_api_pre(const char *fmt, ...);

void log_api(int index, int is_success, uintptr_t return_value,
    const char *fmt, ...);

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg);

void log_new_process();
void log_new_thread();

extern const char *g_explain_apinames[];
extern const char *g_explain_categories[];
extern const char *g_explain_paramtypes[];
extern const char *g_explain_paramnames[][16];

#endif
