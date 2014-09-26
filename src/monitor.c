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
#include "config.h"
#include "dropped.h"
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "monitor.h"
#include "pipe.h"
#include "sleep.h"
#include "unhook.h"

/** Init the monitor
*
* Inits the basic features and hides the module. Also destroys the PE HEADER if not DEBUG-compiled
**/
void monitor_init(HMODULE module_handle)
{
    config_t cfg;
    config_read(&cfg);

    misc_init(cfg.shutdown_mutex);
    dropped_init();
    pipe_init(cfg.pipe_name);

    log_init(cfg.host_ip, cfg.host_port);
    setup_exception_handler();

    sleep_init(cfg.first_process, cfg.force_sleep_skip, cfg.startup_time);

    unhook_init_detection(cfg.first_process);

    // Make sure advapi32 is loaded.
    LoadLibrary("advapi32.dll");

    hide_module_from_peb(module_handle);
#if DEBUG == 0
    destroy_pe_header(module_handle);
#endif
}

/** Iterate through APIs to hook and hook them
*
* library: Library to hook. Can be NULL for hooking everything
**/
void monitor_hook(const char *library)
{
    // TODO Make sure that special hooks are not handled regardless.
    hook_disable();

    for (const hook_t *h = g_hooks; h->funcname != NULL; h++) {
        // If a specific library has been specified then we skip all other
        // libraries. This feature is used in the special hook for LdrLoadDll.
        if(library != NULL && stricmp(h->library, library) != 0) {
            continue;
        }

        if(hook(h->library, h->funcname, h->handler, h->orig,
                h->special) < 0) {
            pipe("CRITICAL:Hooking %z returned failure!", h->funcname);
        }
    }

    hook_enable();
}

/** Send an event to Cuckoo, notifying it that the monitor is ready
**/
void monitor_notify()
{
    hook_disable();

    // Notify Cuckoo that we're good to go.
    char name[64];
    sprintf(name, "CuckooEvent%ld", GetCurrentProcessId());
    HANDLE event_handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, name);
    if(event_handle != NULL) {
        SetEvent(event_handle);
        CloseHandle(event_handle);
    }

    hook_enable();
}

/** Initialises the monitor and hooks
**/
BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        monitor_init(hModule);
        monitor_hook(NULL);
        monitor_notify();
        break;
    }

    return TRUE;
}
