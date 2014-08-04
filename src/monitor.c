#include <stdio.h>
#include <windows.h>
#include "config.h"
#include "dropped.h"
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "pipe.h"

void monitor_init(HMODULE module_handle)
{

    config_t cfg;
    config_read(&cfg);

    misc_init(cfg.shutdown_mutex);
    dropped_init();
    pipe_init(cfg.pipe_name);

    log_init(cfg.host_ip, cfg.host_port);

    // Make sure advapi32 is loaded.
    LoadLibrary("advapi32.dll");

    hide_module_from_peb(module_handle);
}

void monitor_hook()
{
    hook_disable();

    for (const hook_t *h = g_hooks; h->funcname != NULL; h++) {
        if(hook(h->library, h->funcname, h->handler, h->orig) < 0) {
            pipe("CRITICAL:Hooking %z returned failure!", h->funcname);
        }
    }

    hook_enable();
}

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

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        monitor_init(hModule);
        monitor_hook();
        monitor_notify();
        break;
    }

    return TRUE;
}
