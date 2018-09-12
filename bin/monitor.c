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
#include <windows.h>
#include "config.h"
#include "diffing.h"
#include "hooking.h"
#include "ignore.h"
#include "log.h"
#include "memory.h"
#include "misc.h"
#include "monitor.h"
#include "native.h"
#include "pipe.h"
#include "sleep.h"
#include "symbol.h"
#include "unhook.h"

void monitor_init(HMODULE module_handle)
{
    // Sends crashes to the process rather than showing error popup boxes etc.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT |
        SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    config_t cfg;
    config_read(&cfg);

    // Required to be initialized before any logging starts.
    mem_init();

    // Initialize capstone without our custom allocator as it is
    // not available yet.
    hook_init(module_handle);

    pipe_init(cfg.pipe_name, cfg.pipe_pid);
    native_init();

    // Re-initialize capstone with our custom allocator which is now
    // accessible after native_init().
    hook_init2();

    misc_init(cfg.shutdown_mutex);
    diffing_init(cfg.hashes_path, cfg.diffing_enable);

    copy_init();
    log_init(cfg.logpipe, cfg.track);
    ignore_init();

    misc_init2(&monitor_hook, &monitor_unhook);

    sleep_init(cfg.first_process, cfg.force_sleep_skip, cfg.startup_time);

    // Disable the unhook detection for now. TODO Re-enable.
    // unhook_init_detection(cfg.first_process);

    hide_module_from_peb(module_handle);

    if(cfg.disguise != 0) {
        // Set the processor count to two.
        set_processor_count(2);

        // Pretend like we have two extra gigabytes of memory.
        add_virtual_memory(2 * 1024 * 1024 * 1024ull);
    }

    symbol_init(module_handle);

    // Should be the last as some of the other initialization routines extract
    // the image size, EAT pointers, etc while the PE header is still intact.
    destroy_pe_header(module_handle);

    misc_set_monitor_options(cfg.track, cfg.mode, cfg.trigger);
	
	// This is the second part of the UM hook protection
	// Register our exception handler
	register_veh();
}

void monitor_hook(const char *library, void *module_handle)
{
    // Initialize data about each hook.
    for (hook_t *h = sig_hooks(); h->funcname != NULL; h++) {
        // If a specific library has been specified then we skip all other
        // libraries. This feature is used in the special hook for LdrLoadDll.
        if(library != NULL && stricmp(h->library, library) != 0) {
            continue;
        }

        // We only hook this function if the monitor mode is "hook everything"
        // or if the monitor mode matches the mode of this hook.
        if(g_monitor_mode != HOOK_MODE_ALL &&
                (g_monitor_mode & h->mode) == 0) {
            continue;
        }

        // Return value 1 indicates to retry the hook. This is important for
        // delay-loaded function forwarders as the delay-loaded DLL may
        // already have been loaded. In that case we want to hook the function
        // forwarder right away. (Note that the library member of the hook
        // object is updated in the case of retrying).
        while (hook(h, module_handle) == 1);
    }
}

void monitor_unhook(const char *library, void *module_handle)
{
    (void) library;

    for (hook_t *h = sig_hooks(); h->funcname != NULL; h++) {
        // This module was unloaded.
        if(h->module_handle == module_handle) {
            h->is_hooked = 0;
            h->addr = NULL;
        }

        // This is a hooked function which doesn't belong to a particular DLL.
        // Therefore the module handle is a nullptr and we simply check
        // whether the address of the original function is still in-memory.
        if(h->module_handle == NULL && range_is_readable(h->addr, 16) == 0) {
            h->is_hooked = 0;
            h->addr = NULL;
        }
    }
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) lpReserved;

    if(dwReason == DLL_PROCESS_ATTACH && is_ignored_process() == 0) {
        monitor_init(hModule);
        monitor_hook(NULL, NULL);
        pipe("LOADED:%d,%d", get_current_process_id(), g_monitor_track);
    }

    return TRUE;
}
