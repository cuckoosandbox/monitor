#include <stdio.h>
#include <windows.h>
#include "config.h"
#include "dropped.h"
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "pipe.h"

config_t g_config;

void monitor_init()
{
    hook_info()->hook_count++;

    config_read(&g_config);

    misc_init();
    dropped_init();
    pipe_init(g_config.pipe_name);

    log_init(g_config.host_ip, g_config.host_port);

    for (const hook_t *h = g_hooks; h->funcname != NULL; h++) {
        if(hook(h->library, h->funcname, h->handler, h->orig) < 0) {
            pipe("CRITICAL:Hooking %z returned failure!", h->funcname);
        }
    }

    hook_info()->hook_count--;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void) hModule; (void) lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        monitor_init();
        break;
    }

    return TRUE;
}
