/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2017 Cuckoo Foundation.

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

#include <wbemidl.h>
#include <bits.h>
#include "hooking.h"
#include "misc.h"
#include "ole.h"
#include "pipe.h"

static IBackgroundCopyJobVtbl *g_bgcj_vtbl = NULL;

void bits_set_job_vtable(IBackgroundCopyJobVtbl *bgcj)
{
    g_bgcj_vtbl = bgcj;
}

static int _locate_background_copy_manager(
    hook_t *h, IBackgroundCopyManager **bgcm)
{
    pipe("INFO:LOOKING AT BGCJ");
    if(init_co_create_instance() < 0) {
        return -1;
    }

    HRESULT res = pCoCreateInstance(
        &our_CLSID_BackgroundCopyManager, NULL,
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        &our_IID_IBackgroundCopyManager, (void **) bgcm
    );
    if(res == CO_E_NOTINITIALIZED) {
        return -1;
    }
    if(SUCCEEDED(res) == FALSE) {
        pipe("WARNING:Error creating IBackgroundCopyManager instance "
            "error=0x%x [aborting hook %z]", res, h->funcname);
        return -1;
    }
    return 0;
}

uint8_t *hook_addrcb_IBackgroundCopyManager_CreateJob(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) module_address; (void) module_size;

    IBackgroundCopyManager *background_copy_manager = NULL;
    if(_locate_background_copy_manager(h, &background_copy_manager) < 0) {
        return NULL;
    }

    uint8_t *ret = (uint8_t *) background_copy_manager->lpVtbl->CreateJob;

    pipe("INFO:found createjob @ 0x%X", ret);
    background_copy_manager->lpVtbl->Release(background_copy_manager);
    return ret;
}

uint8_t *hook_addrcb_IBackgroundCopyJob_AddFile(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h; (void) module_address; (void) module_size;

    if(g_bgcj_vtbl == NULL) {
        return NULL;
    }

    return (uint8_t *) g_bgcj_vtbl->AddFile;
}

uint8_t *hook_addrcb_IBackgroundCopyJob_AddFileSet(
    hook_t *h, uint8_t *module_address, uint32_t module_size)
{
    (void) h; (void) module_address; (void) module_size;

    if(g_bgcj_vtbl == NULL) {
        return NULL;
    }

    return (uint8_t *) g_bgcj_vtbl->AddFileSet;
}
