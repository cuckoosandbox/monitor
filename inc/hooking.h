#ifndef MONITOR_HOOKING_H
#define MONITOR_HOOKING_H

#include <stdint.h>
#include <windows.h>
#include "slist.h"

typedef struct _hook_info_t {
    uint32_t hook_count;
    uint32_t last_error;

    slist_t retaddr;
} hook_info_t;

typedef struct _hook_data_t {
    uint8_t *trampoline;
    uint8_t *guide;
    uint8_t *func_stub;
    uint8_t *clean;

    uint8_t *_mem;
} hook_data_t;

typedef struct _hook_t {
    const char *library;
    const char *funcname;
    FARPROC handler;
    FARPROC *orig;

    hook_data_t *data;
} hook_t;

hook_info_t *hook_alloc();
hook_info_t *hook_info();

int hook(const char *library, const char *funcname,
    FARPROC handler, FARPROC *orig);

int hook2(hook_t *h);

extern const hook_t g_hooks[];

#endif
