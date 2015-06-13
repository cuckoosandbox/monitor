Signature::

    * Calling convention: WINAPI


COleScript_Compile
==================

Signature::

    * Callback: addr
    * Is success: ret >= 0
    * Library: jscript
    * Special: true
    * Return value: int

Parameters::

    *  void *this
    *  void *script_body
    ** const wchar_t *script
    *  uint32_t unk1
    *  uint32_t unk2
    *  uint32_t unk3
    ** const wchar_t *type
    *  void *exception


CDocument_write
===============

Signature::

    * Callback: addr
    * Is success: 1
    * Library: mshtml
    * Special: true
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
