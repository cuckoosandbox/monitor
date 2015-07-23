Signature::

    * Callback: addr
    * Calling convention: WINAPI
    * Category: iexplore
    * Logging: always
    * Mode: iexplore
    * Special: true


COleScript_Compile
==================

Signature::

    * Is success: ret >= 0
    * Library: jscript
    * Return value: int

Parameters::

    *  void *this
    *  void *script_body
    ** const wchar_t *script
    *  uintptr_t unk1
    *  uintptr_t unk2
    *  uintptr_t unk3
    ** const wchar_t *type
    *  void *exception


CDocument_write
===============

Signature::

    * Is success: 1
    * Library: mshtml
    * Return value: int

Parameters::

    *  void *cdocument
    *  SAFEARRAY *arr

Middle::

    bson b; char index[8];
    bson_init_size(&b, mem_suggested_size(4096));

    VARIANT *elements = (VARIANT *) arr->pvData;
    for (uint32_t idx = 0, jdx = 0; idx < arr->rgsabound[0].cElements;
            idx++, elements++) {
        if(elements->vt == VT_BSTR && elements->bstrVal != NULL) {
            uint32_t length = *(uint32_t *)(
                (uint8_t *) elements->bstrVal - sizeof(uint32_t));

            our_snprintf(index, sizeof(index), "%d", jdx++);
            log_wstring(&b, index, elements->bstrVal,
                length / sizeof(wchar_t));
        }
    }

    bson_finish(&b);

Logging::

    z lines &b

Post::

    bson_destroy(&b);


CHyperlink_SetUrlComponent
==========================

Signature::

    * Is success: 1
    * Library: mshtml
    * Return value: int

Parameters::

    *  void *chyperlink
    ** const wchar_t *component
    ** int index


CIFrameElement_CreateElement
============================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *chtmtag
    *  void *cdoc
    *  void **celement

Middle::

    bson b;

    bson_init_size(&b, mem_suggested_size(1024));
    chtmtag_attrs(chtmtag, &b);
    bson_finish(&b);

Logging::

    z attributes &b

Post::

    bson_destroy(&b);


CWindow_AddTimeoutCode
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *cwindow
    *  VARIANT *data
    ** const wchar_t *argument
    ** int milliseconds
    *  int repeat
    *  void *unk2

Pre::

    wchar_t *code = NULL;
    if(data != NULL && data->vt == VT_BSTR) {
        code = data->bstrVal;
    }

Logging::

    u code code
    i repeat repeat != 0


CScriptElement_put_src
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *cscriptelement
    ** const wchar_t *url


CElement_put_innerHTML
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *celement
    ** const wchar_t *html
