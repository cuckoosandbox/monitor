Signature::

    * Callback: addr
    * Calling convention: WINAPI
    * Category: misc
    * Library: __wmi__
    * Mode: exploit
    * Prune: resolve
    * Return value: HRESULT


IWbemServices_ExecQuery
=======================

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** ULONG lFlags flags
    *  IWbemContext *pCtx
    *  IEnumWbemClassObject **ppEnum


IWbemServices_ExecQueryAsync
============================

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemObjectSink *pResponseHandler


IWbemServices_ExecMethod
========================

Parameters::

    *  IWbemServices *This
    ** const wchar_t *strObjectPath class
    ** const wchar_t *strMethodName method
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemClassObject *pInParams
    *  IWbemClassObject **ppOutParams
    *  IWbemCallResult **ppCallResult

Pre::

    int adjusted = -1; uint32_t creation_flags = 0;

    // We adjust some parameters for Win32_Process::Create so we can follow
    // the newly created process cleanly.
    if(wcscmp(strObjectPath, L"Win32_Process") == 0 &&
            wcscmp(strMethodName, L"Create") == 0) {
        adjusted = wmi_win32_process_create_pre(
            This, pInParams, &creation_flags
        );
    }

Post::

    HRESULT hr; VARIANT vt; uint32_t pid = 0, tid = 0;

    if(adjusted == 0 && SUCCEEDED(ret) != FALSE) {
        vt.vt = VT_EMPTY;
        hr = (*ppOutParams)->lpVtbl->Get(
            *ppOutParams, L"ProcessId", 0, &vt, NULL, NULL
        );
        if(SUCCEEDED(hr) != FALSE && vt.vt == VT_I4) {
            pid = vt.uintVal; tid = first_tid_from_pid(pid);
            pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);
        }

        if((creation_flags & CREATE_SUSPENDED) == 0 && tid != 0) {
            resume_thread_identifier(tid);
        }

        sleep_skip_disable();
    }


IWbemServices_ExecMethodAsync
=============================

Parameters::

    *  IWbemServices *This
    ** const BSTR strObjectPath class
    ** const BSTR strMethodName method
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemClassObject *pInParams
    *  IWbemObjectSink *pResponseHandler

Pre::

    // TODO Implement process following functionality.
