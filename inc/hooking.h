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

#ifndef MONITOR_HOOKING_H
#define MONITOR_HOOKING_H

#include <stdint.h>
#include <windows.h>
#include "monitor.h"

#define RETADDRCNT 64

#define HOOK_PRUNE_RESOLVERR 1

#define HOOK_MODE_ALL      0
#define HOOK_MODE_DUMPTLS  1
#define HOOK_MODE_IEXPLORE 2
#define HOOK_MODE_EXPLOIT  4

typedef struct _hook_t {
    // Library and function name.
    const char *library;
    const char *funcname;

    // Hook handler.
    FARPROC handler;

    // Callback to the original function.
    FARPROC *orig;

    // Is this a "special" hook?
    int special;

    // Various flags on limiting the amount of non-critical errors shown
    // related to API hooks.
    int report;

    // Mode indicating in which monitor modes this hook should be enabled.
    int mode;

    // Special address resolve callback for this function hook. It is called
    // in order to resolve the address of the function to be hooked.
    uint8_t *(*addrcb)(struct _hook_t *h,
        uint8_t *module_address, uint32_t module_size);

    // Special initialization callback for this function hook. It is called
    // right after the hooking has successfully taken place.
    void (*initcb)(struct _hook_t *h);

    // Address of the module.
    void *module_handle;

    // Address of the hooked function.
    uint8_t *addr;

    // Amount of bytes to skip before placing the hook. I.e., hook
    // at addr+skip instead of addr.
    uint32_t skip;

    // Total size used to create our stub off.
    int32_t stub_used;

    // Is this function already hooked?
    uint32_t is_hooked;

    // Stub for calling the original function.
    uint8_t *func_stub;
} hook_t;

// Hook initialization part one and two. One should be called before having
// initialized the native functionality for memory allocation, two afterwards.
int hook_init(HMODULE module_handle);
int hook_init2();

int lde(const void *addr);

int hook_in_monitor();

int hook(hook_t *h, void *module_handle);
int hook_missing_hooks(HMODULE module_handle);

#define DISASM_BUFSIZ 128

int disasm(const void *addr, char *str);

hook_t *sig_hooks();
uint32_t sig_hook_count();

void hook_initcb_LdrLoadDll(hook_t *h);

uint8_t *hook_addrcb_RtlDispatchException(hook_t *h,
    uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_COleScript_Compile(hook_t *h,
    uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CDocument_write(hook_t *h,
    uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CHyperlink_SetUrlComponent(hook_t *h,
    uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CIFrameElement_CreateElement(hook_t *h,
    uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CWindow_AddTimeoutCode(
    hook_t *h, uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CScriptElement_put_src(
    hook_t *h, uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_CElement_put_innerHTML(
    hook_t *h, uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_PRF(
    hook_t *h, uint8_t *module_address, uint32_t module_size);
uint8_t *hook_addrcb_Ssl3GenerateKeyMaterial(
    hook_t *h, uint8_t *module_address, uint32_t module_size);

int iexplore_should_propagate_monitor_mode(const wchar_t *cmdline);

#endif
