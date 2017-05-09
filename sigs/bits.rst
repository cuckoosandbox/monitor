Signature::

    * Callback: addr
    * Category: misc
    * Mode: exploit
    * Prune: resolve
    * Return value: HRESULT

IBackgroundCopyManager_CreateJob
================================

Signature::

    * Calling convention: __thiscall
    * Library: __bits__

Parameters::

    ** IBackgroundCopyManager *This
    ** LPCWSTR DisplayName jobname
    ** int Type
    ** GUID *pJobId
    ** IBackgroundCopyJob **ppJob

Pre::

    const char *jobtype = NULL;
    if(Type == BG_JOB_TYPE_DOWNLOAD) {
        jobtype = "download";
    }
    else if(Type == BG_JOB_TYPE_UPLOAD) {
        jobtype = "upload";
    }
    else if(Type == BG_JOB_TYPE_UPLOAD_REPLY) {
        jobtype = "upload_reply";
    }

Logging::

    s jobtype jobtype

Post::

    IUnknown *obj = NULL; HRESULT hr;

    hr = This->lpVtbl->QueryInterface(
        This, &our_IID_IBackgroundCopyManager, (void **) &obj
    );
    if(SUCCEEDED(hr) != FALSE && obj != NULL) {
        obj->lpVtbl->Release(obj);
    }

    pipe("INFO:inside createjob..");
    if(SUCCEEDED(ret) != FALSE && SUCCEEDED(hr) != FALSE) {
        char buf[128];
        hexdump(buf,  ppJob, 32); pipe("INFO:lots of success1.. %z", buf);
        hexdump(buf, *ppJob, 32); pipe("INFO:lots of success2.. %z", buf);
        bits_set_job_vtable(copy_ptr(copy_ptr(ppJob)));
        hook_library("__bits2__", NULL);
        pipe("INFO:we're still alive..");
    }


IBackgroundCopyJob_AddFile
==========================

Signature::

    * Calling convention: WINAPI
    * Library: __bits2__

Parameters::

    *  IBackgroundCopyJob *This
    ** LPCWSTR pRemoteName remote
    ** LPCWSTR pLocalName local


IBackgroundCopyJob_AddFileSet
=============================

Signature::

    * Calling convention: WINAPI
    * Library: __bits2__

Parameters::

    *  IBackgroundCopyJob *This
    *  ULONG cFileCount
    *  BG_FILE_INFO *paFileSet

Pre::

    // For now we're just going to take the first element - this should be
    // improved in the future.
    const wchar_t *remote = NULL, *local = NULL;
    for (uint32_t idx = 0; idx < cFileCount; idx++) {
        pipe(
            "INFO:addfile %Z => %Z",
            paFileSet[idx].RemoteName != NULL ? paFileSet[idx].RemoteName : L"",
            paFileSet[idx].LocalName != NULL ? paFileSet[idx].LocalName : L""
        );
    }
    if(cFileCount >= 1 && paFileSet != NULL) {
        remote = paFileSet->RemoteName;
        local = paFileSet->LocalName;
    }

Logging::

    u remote remote
    u local local
