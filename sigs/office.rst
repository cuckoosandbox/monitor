Signature::

    * Callback: module
    * Category: office
    * Is success: 1
    * Library: vbe6
    * Logging: always
    * Mode: office
    * Return value: void *
    * Special: true

_vbe6_StringConcat
==================

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


vbe6_CallByName
===============

Signature::

    * Calling convention: WINAPI

Parameters::

    *  void *result
    *  void *this
    *  const wchar_t *funcname
    *  void *unk1
    *  SAFEARRAY **args
    *  void *unk3

Pre::

    vbe6_set_funcname(funcname);


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

    wchar_t *funcname = vbe6_get_funcname();

Middle::

    bson b2;

    bson_init_size(&b2, mem_suggested_size(4096));

    if(result != NULL) {
        variant_to_bson(&b2, "0", result, NULL);
    }
    else {
        bson_append_null(&b2, "0");
    }

    bson_finish(&b2);

Logging::

    u funcname funcname
    z args &b
    z result &b2

Post::

    bson_destroy(&b);
    bson_destroy(&b2);
    mem_free(funcname);


vbe6_Shell
==========

Signature::

    * Calling convention: WINAPI

Parameters::

    ** const VARIANT *command_line
    ** int show_type


vbe6_Import
===========

Signature::

    * Calling convention: WINAPI

Parameters::

    *  void **args
    *  void *unk1
    *  void *unk2
    *  void *unk3
    *  void *unk4

Logging::

    s library args[0]
    s function args[1]


vbe6_Open
=========

Signature::

    * Calling convention: WINAPI

Parameters::

    ** int mode
    *  void *unk1
    ** int fd
    ** const wchar_t *filename filename


vbe6_Print
==========

Signature::

    * Calling convention: WINAPI

Parameters::

    *  void *unk1
    *  void *unk2
    ** const VARIANT *buf
    *  void *unk4

Pre::

    // TODO Figure out where to locate the fd.


vbe6_Close
==========

Signature::

    * Calling convention: __thiscall

Parameters::

    *  void *this
    ** int fd
