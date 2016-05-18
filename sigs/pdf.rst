Signature::

    * Callback: module
    * Calling convention: __cdecl
    * Category: pdf
    * Is success: 1
    * Library: escript.api
    * Logging: always
    * Mode: pdf
    * Return value: void *
    * Special: true


pdf_eval
========

Signature::

    * Prelog: instant

Parameters::

    *  void *unk1
    *  void *unk2
    *  void *unk3
    *  void *args
    *  void *unk4

Logging::

    u script copy_ptr(copy_ptr(args))


pdf_unescape
============

Parameters::

    *  void *unk1
    *  void *unk2
    *  void *unk3
    *  void *args
    *  void *unk4

Logging::

    u string copy_ptr(copy_ptr(args))
