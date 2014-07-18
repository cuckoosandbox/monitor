#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "pipe.h"

void monitor_init()
{
    hook_alloc()->hook_count++;

    misc_init();

    uint32_t ip_address = inet_addr("192.168.56.1");
    log_init(ip_address, 2042);

    log_explain();

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
