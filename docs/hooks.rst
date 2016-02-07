.. _hook-create:

==============
Creating Hooks
==============

Creating new hooks is as simple as understanding the ``signature`` format,
knowing the correct ``return value`` and ``arguments``, finding the correct
signature file to put it in, and optionally know the somewhat more advanced
features.

Signature Format
================

The ``signature format`` is a very basic ``reStructuredText``-based way to
describe an API signature. This signature is pre-processed by
``utils/process.py`` to emit C code which is in turn compiled into the
Monitor.

Following is an example signature of ``system()``:

.. code-block:: rst

    system
    ======

    Signature::

        * Calling convention: WINAPI
        * Category: process
        * Is success: ret == 0
        * Library: msvcrt
        * Return value: int

    Parameters::

        ** const char *command

The ``Signature`` block describes meta-information about the API function. The
``Parameters`` block has a list of all parameters to the function. There are
also ``Pre``, ``Prelog``, ``Logging``, and ``Post`` blocks. Following are all
blocks described with their syntax and features - in their prefered order.

General Syntax
--------------

Each API signature starts with a small header containing the API name.

.. code-block:: rst

    FunctionName
    ============

Followed is at least one block - the :ref:`hook-block-signature`. Each block
has the block name followed by two colons, followed by one or more indented
lines according to the blocks' syntax.

.. code-block:: rst

    FunctionName
    ============

    Block::

        Line #1
        Line #2
        Line #3
        ...

    Block2::

        Line #1
        Line #2

It is recommended to keep the signatures clean and standard:

* One blank line between the API name header and the first block.
* One blank line between a block name and its contents.
* One blank line between blocks.
* Two lines between each API signature.

Available Blocks
================

.. _hook-block-signature:

Signature Block
---------------

The signature block describes meta-information for each API signature. The
syntax for each line in the signature block is as follows.

.. code-block:: rst

    Signature::

        * key: value

The key is converted to lowercase and spaces are replaced by underscores, the
value is kept as-is.

Available keys:

* Calling Convention:

    The calling convention of this API function. This value should be be set
    to WINAPI.

* Category:

    The category of this API signature, e.g., file, process, or crypto.

* Library:

    The DLL name of the library, e.g., kernel32 or ntdll.

* Return value:

    The return value of this function. To determine whether a function call
    was successful (the "is-success" flag) there are definitions for most
    common data types. However, some functions return an int or DWORD - these
    have to be handled on a per-API basis.

* Is success:

    This key is only required for non-standard return values. E.g., if an API
    function returns an int or DWORD then it's really up to the function to
    describe when it's return success or failure. However, most cases can be
    generalized.

    Following is a list of all available data types which have a pre-defined
    is-success definition.

    .. literalinclude:: ../data/is-success.conf

* Special:

    Mark this API signature as ``special``. Special API signatures are always
    executed, also when the monitor is already *inside* another hook. E.g.,
    when executing the ``system()`` function we still want to follow the
    ``CreateProcessInternalW()`` function calls in order to catch the process
    identifier(s) of the child process(es), allowing the monitor to inject
    into said child process(es).

.. _hook-block-parameters:

Parameters Block
----------------

The parameter block describes each parameter that the function accepts - one
per line. Its syntax is either of the following::

    *  DataType VariableName
    ** DataType VariableName
    ** DataType VariableName variable_name

One asterisks indicates this parameter should not be logged. Two asterisks
indicate that this variable should be logged. Finally, if a third argument is
given, then this indicates the ``alias``. In the reports you'll see the
``alias``, or the ``VariableName`` if no alias was given, as key. Due to
consistency it is recommended to use the original variable names as described
in the API prototypes and to use lowercase aliases as Cuckoo-specific names.

.. _hook-block-flags:

Flags Block
-----------

This block describes values which are flags and that we would like the string
representation.
Its syntax should be as follows::

    <name> <value> <flag-type>

The ``name`` should be either :
 - ``variable_name`` (or ``VariableName`` if no alias was given)
   (see :ref:`hook-block-parameters`). In this case, you will get meaning of
   the specified parameter arg as described in flag file. (See :ref:`flag-format`)
   ``value`` and ``flag-type`` will be overwritten as follows:
    - ``value``  =  ``VariableName`` 
    - ``flag-type``  =  ``<apiname>_<VariableName>``
 - A unique name alias. Here it's mandatory to provide :
    - ``value`` : any C expression which is a flag
    - ``flag-type`` : Flag type block in flag file. (See :ref:`flag-format`)

.. _hook-block-ensure:

Ensure Block
------------

The ensure block describes which parameters should never be null pointers. As
an example, the ``ReadFile`` function has the ``lpNumberOfBytesRead``
parameter as optional. However, in order to make sure we know exactly how many
bytes have been read we'd like to have this value at all times. This is where
the ensure block makes sure the ``lpNumberOfBytesRead`` is not NULL.

Its syntax is a line for each parameter's VariableName:

.. code-block:: rst

    Ensure::

        lpNumberOfBytesRead

.. _hook-block-pre:

Pre Block
---------

The pre block allows one to execute code before any other code in the hook
handler. For example, when a file is deleted using the ``DeleteFile``
function, the Monitor will first want to notify Cuckoo in order to make sure
it can make a backup of the file before it is being deleted (also known as
``dropped files`` in Cuckoo reports.)

There is no special syntax for pre blocks - its lines are directly included
as C code in the generated C hooks source.

As an example, a stripped down example of ``DeleteFileA``'s pre block::

    Pre::

        pipe("FILE_NEW:%z", lpFileName);

.. _hook-block-prelog:

Prelog Block
------------

The prelog block allows buffers to be logged before calling the original
function. In functions that encrypt data possibly into the original buffer
this is useful to be able to log the plaintext buffer rather than the
encrypted buffer. (See for example the signature for ``CryptProtectData``.)

The prelog block has the same syntax as the :ref:`hook-block-logging` except
for the fact that at the moment only **one** ``buffer`` line is supported.
(Mostly because there has been no need for other data types or multiple
buffers yet.)

.. _hook-block-middle:

Middle Block
------------

The middle block executes arbitrary C code after the original function has
been called but before the function call has been logged. Its syntax is equal
to the :ref:`hook-block-pre`.

.. _hook-replace-block:

Replace Block
-------------

The replace block allows one to replace the parameters used when calling the
original function. This is useful when a particular argument has to be swapped
out for another parameter.

.. _hook-block-logging:

Logging Block
-------------

The logging block describes data that should be logged after the original
function has been called but that is not really possible to explain in the
:ref:`hook-block-parameters`. For example, many functions such as ``ReadFile``
and ``WriteFile`` pass around buffers which are described by a length
parameter and a parameter with a pointer to the buffer.

Each line in the logging block should be as follows:

.. code-block:: rst

    Logging::

        <format-specifier> <parameter-alias> <the-value>

The ``format specifier`` should be one of the values as described in
``inc/pipe.h``. The alias is much like the aliases from
:ref:`hook-block-parameters`. The value is any C expression that will get the
correct value.

Following are some examples (with stripped down API signatures):

.. code-block:: rst

    ReadFile
    ========

    Logging::

        B buffer lpNumberOfBytesRead, lpBuffer


    CreateProcessInternalW
    ======================

    Ensure::

        lpProcessInformation

    Logging::

        i process_identifier lpProcessInformation->dwProcessId
        i thread_identifier lpProcessInformation->dwThreadId


.. _hook-block-post:

Post Block
----------

The post block executes arbitrary C code after the original function has been
called and after the function call has been logged. Its syntax is equal to the
:ref:`hook-block-pre`.

Logging API
===========

In order to easily log the hundreds of parameters that the various API
signatures feature a standardized logging format string has been developed
that supports all currently-used data types.

The ``log_api()`` function accepts such format strings. However, one does not
have to call this function as the calls to ``log_api()`` is automatically
generated by the Python pre-processor script. (In fact, this would currently
result in undefined behavior, so don't do it.)

Logging Format Specifier
------------------------

Following is a list of all currently supported format specifiers:

* ``s``: zero-terminated ascii string
* ``S``: ascii string with length
* ``u``: zero-terminated unicode string
* ``U``: unicode string with length in characters
* ``b``: buffer pointer with length
* ``B``: buffer pointer with pointer to length
* ``i``: 32-bit integer
* ``l``: 32-bit or 64-bit long
* ``p``: pointer address
* ``P``: pointer to pointer address
* ``o``: pointer to ``ANSI_STRING``
* ``O``: pointer to ``UNICODE_STRING``
* ``x``: pointer to ``OBJECT_ATTRIBUTES``
* ``a``: array of zero-terminated ascii strings
* ``A``: array of zero-terminated unicode strings
* ``r``: registry stuff - to be updated
* ``R``: registry stuff - to be updated
* ``q``: 64-bit integer
* ``Q``: pointer to 64-bit integer (e.g., pointer to ``LARGE_INTEGER``)
* ``z``: bson object
* ``c``: REFCLSID object

.. _flag-format:

Flag Format
===========

The ``flag format`` is a very basic ``reStructuredText``-based way to
describe meaning of bit flag argument in Windows API.
It is found in ``flags/``
This flag is pre-processed by ``utils/process.py`` to emit C code
which is in turn compiled into the Monitor.

General Syntax
--------------

Each flag starts with a small header containing the flag type.

.. code-block:: rst

    FlagType
    ========

Followed is at least one block. Each block has the block name followed
by two colons, followed by one or more indented lines according to the
blocks' syntax.

.. code-block:: rst

    FlagType
    ========

    Block::

        <value>
        <value1>
        <value2>
        ...

    Block2::

        <value1>
        <value2>

It is recommended to keep flags clean and standard:

* One blank line between the Flag type header and the first block.
* One blank line between a block name and its contents.
* One blank line between blocks.
* Two lines between each flag type.

Available Blocks
================

.. _flag-block-inherits:

Inherits Block
--------------

.. _flag-block-value:

Value Block
-----------

This block defines possible values when only one flag could be set.

.. _flag-block-enum:

Enum block
----------

This block defines possible values in a bitwise manner.
