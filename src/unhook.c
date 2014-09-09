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

#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "pipe.h"
#include "log.h"
#include "misc.h"

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 256

typedef struct _region_t {
    uint32_t        region_length;
    const uint8_t  *region_address;
    uint8_t         region_original[UNHOOK_BUFSIZE];
    uint8_t         region_modified[UNHOOK_BUFSIZE];

    char            funcname[64];
    uint32_t        region_reported;
} region_t;

static HANDLE g_unhook_thread_handle, g_watcher_thread_handle, g_main_thread;
static uint32_t g_region_index, g_unhook_exited;
static region_t g_regions[UNHOOK_MAXCOUNT];

void unhook_detect_add_region(const char *funcname, const uint8_t *addr,
    const uint8_t *original, const uint8_t *modified, uint32_t length)
{
    if(g_region_index == UNHOOK_MAXCOUNT) {
        pipe("CRITICAL:Reached maximum number of unhook detection entries!");
        return;
    }

    region_t *r = &g_regions[g_region_index];

    r->region_length = length;
    r->region_address = addr;

    if(funcname != NULL) {
        strcpy(r->funcname, funcname);
    }

    memcpy(r->region_original, original, MIN(length, UNHOOK_BUFSIZE));
    memcpy(r->region_modified, modified, MIN(length, UNHOOK_BUFSIZE));

    g_region_index++;
}

static DWORD WINAPI _unhook_detect_thread(LPVOID param)
{
    (void) param;

    static int watcher_first = 1;

    hook_disable();

    while (g_main_thread == NULL ||
            WaitForSingleObject(g_main_thread, 10) == WAIT_TIMEOUT) {
        if(WaitForSingleObject(g_watcher_thread_handle,
                500) != WAIT_TIMEOUT) {
            if(watcher_first != 0) {
                if(is_shutting_down() == 0) {
                    log_anomaly("unhook", 1, NULL,
                        "Unhook watcher thread has been corrupted!");
                }
                watcher_first = 0;
            }
            Sleep(100);
        }

        for (uint32_t idx = 0; idx < g_region_index; idx++) {
            region_t *r = &g_regions[g_region_index];

            // Check whether this memory region still equals what we made it.
            if(memcmp(r->region_address, r->region_modified,
                    r->region_length) == 0) {
                continue;
            }

            // By default we assume the hook has been modified.
            const char *msg = "Function hook was modified!";

            // If the memory region matches the original contents, then it
            // has been restored to its original state.
            if(memcmp(r->region_address, r->region_original,
                    r->region_length) == 0) {
                msg = "Function was unhooked/restored!";
            }

            if(r->region_reported == 0) {
                if(is_shutting_down() == 0) {
                    log_anomaly("unhook", 1, r->funcname, msg);
                }
                r->region_reported = 1;
            }
        }
    }

    g_unhook_exited = 1;
    return 0;
}

static DWORD WINAPI _unhook_watch_thread(LPVOID param)
{
    (void) param;

    hook_disable();

    while (WaitForSingleObject(g_unhook_thread_handle, 1000) == WAIT_TIMEOUT);

    if(g_unhook_exited == 0 && is_shutting_down() == 0) {
        log_anomaly("unhook", 1, NULL,
            "Unhook detection thread has been corrupted!");
    }
    return 0;
}

int unhook_init_detection(int first_process)
{
    g_unhook_exited = 0;

    if(first_process != 0) {
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
            GetCurrentProcess(), &g_main_thread, 0,
            FALSE, DUPLICATE_SAME_ACCESS);
    }

    g_unhook_thread_handle =
        CreateThread(NULL, 0, &_unhook_detect_thread, NULL, 0, NULL);

    g_watcher_thread_handle =
        CreateThread(NULL, 0, &_unhook_watch_thread, NULL, 0, NULL);

    if(g_unhook_thread_handle != NULL && g_watcher_thread_handle != NULL) {
        return 0;
    }

    pipe("CRITICAL:Error initializing unhook detection threads!");
    return -1;
}
