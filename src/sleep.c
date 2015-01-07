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

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "sleep.h"

static uint32_t g_sleep_skip_active;
static uint32_t g_sleep_max_skip;
static uint32_t g_sleep_force_skip;

static LARGE_INTEGER g_time_skipped;
static LARGE_INTEGER g_time_start;

void sleep_init(int first_process, uint32_t force_skip, uint32_t startup_time)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    g_time_start.HighPart = ft.dwHighDateTime;
    g_time_start.LowPart = ft.dwLowDateTime;

    g_sleep_skip_active = 1;

    // TODO Make this configurable.
    g_sleep_max_skip = 5000;

    g_sleep_force_skip = force_skip;

    g_time_skipped.QuadPart = (uint64_t) startup_time * 10000;

    if(first_process == 0) {
        sleep_skip_disable();
    }
}

int sleep_skip(LARGE_INTEGER *delay)
{
    FILETIME ft; LARGE_INTEGER li;

    if(g_sleep_skip_active != 0) {
        GetSystemTimeAsFileTime(&ft);
        li.HighPart = ft.dwHighDateTime;
        li.LowPart = ft.dwLowDateTime;

        // Check whether we're within the maximum limit of skipping.
        if(li.QuadPart < g_time_start.QuadPart + g_sleep_max_skip * 10000) {
            g_time_skipped.QuadPart += -delay->QuadPart;

            // Replace the time by a tenth of a millisecond.
            delay->QuadPart = -1000;
            return 1;
        }

        // TODO Should this depend on 'force-skip' or not?
        sleep_skip_disable();
    }

    return 0;
}

void sleep_skip_disable()
{
    if(g_sleep_force_skip == 0) {
        g_sleep_skip_active = 0;
    }
}

void sleep_apply_filetime(FILETIME *ft)
{
    LARGE_INTEGER li;

    li.HighPart = ft->dwHighDateTime;
    li.LowPart = ft->dwLowDateTime;
    li.QuadPart += g_time_skipped.QuadPart;
    ft->dwHighDateTime = li.HighPart;
    ft->dwLowDateTime = li.LowPart;
}

void sleep_apply_systemtime(SYSTEMTIME *st)
{
    FILETIME ft;

    SystemTimeToFileTime(st, &ft);
    sleep_apply_filetime(&ft);
    FileTimeToSystemTime(&ft, st);
}

uint64_t sleep_skipped()
{
    return g_time_skipped.QuadPart;
}
