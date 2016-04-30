Signature::

    * Callback: module
    * Category: office
    * Is success: 1
    * Library: vbe6
    * Logging: always
    * Mode: office
    * Return value: void *
    * Special: true

vbe6_StringConcat
=================

Signature::

    * Calling convention: __thiscall

Parameters::

    *  void *this
    *  VARIANT *dst
    *  VARIANT *src2
    *  VARIANT *src1

Logging::

    v dst dst
    v src1 src1
    v src2 src2


vbe6_CreateObject
=================

Signature::

    * Calling convention: WINAPI

Parameters::

    ** void **this
    ** const BSTR object_name
    *  void *unk1

Logging::

    p this this[2]


vbe6_GetObject
==============

Signature::

    * Calling convention: WINAPI

Parameters::

    *  void **this
    ** const VARIANT *object_name
    *  void *unk1

Logging::

    p this this[2]


vbe6_GetIDFromName
==================

Signature::

    * Calling convention: WINAPI

Parameters::

    ** const wchar_t *funcname
    ** void *this

Logging::

    l funcidx ret


vbe6_Invoke
===========

Signature::

    * Calling convention: WINAPI

Parameters::

    ** void *this
    ** int funcidx
    *  void *unk1
    *  void *unk2
    *  void *unk3
    *  uint8_t *args
    *  VARIANT *result
    *  void *unk8
    *  void *unk9

Pre::

    bson b;

    bson_init_size(&b, mem_suggested_size(4096));
    bson_append_start_array(&b, "bson");

    if(args != NULL) {
        vbe6_invoke_extract_args(args, &b);
    }

    bson_append_finish_array(&b);
    bson_finish(&b);

Middle::

    bson b2;

    bson_init_size(&b2, mem_suggested_size(4096));

    if(result != NULL) {
        variant_to_bson(&b2, "0", result);
    }
    else {
        bson_append_null(&b2, "0");
    }

    bson_finish(&b2);

Logging::

    z args &b
    z result &b2

Post::

    bson_destroy(&b);
    bson_destroy(&b2);


vbe6_Shell
==========

Signature::

    * Calling convention: WINAPI

Parameters::

    ** const VARIANT *command_line
    ** int show_type
