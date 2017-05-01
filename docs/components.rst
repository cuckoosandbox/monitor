.. _components:

Components
==========

The Monitor exists of a few different components which as a whole represent
the project.

* :ref:`components-c`
* :ref:`components-asm`
* :ref:`components-hook`
* (:ref:`components-py`)

.. _components-c:

C Framework
-----------

The majority of the Monitor has been implemented in C as this allows the most
flexibility at runtime. The code can be found in ``src/`` and all related
headers in ``inc/``.

The C Framework includes the following functionality (and more):

* Hooking::

    Wrapper around the assembly snippets and creation of original function
    stub.

* Dropped Files::

    Special handling for file operations in order to automatically dump files
    that are dropped by a particular sample.

* Sleep Skip::

    Ability to (force) skip long sleeps which tend to make Cuckoo run into the
    analysis timeout.

* Unhook Detection::

    Thread that regularly checks whether all function hooks are still as we
    left them. This feature can detect samples that attempt to unhook or
    overwrite the Monitor's hooks.

* Filtering::

    Basic filtering of common windows-related filepaths that are generally
    not interesting to Cuckoo.

.. _components-asm:

Assembly snippets
-----------------

In order to correctly handle API hooking at runtime a few layers of
indirection are being used. Listed in order of execution:

* :ref:`hook-asm-tramp`
* :ref:`hook-asm-guide`
* :ref:`hook-asm-clean`

.. _hook-asm-tramp:

Hook Trampoline
^^^^^^^^^^^^^^^

When a sample injected with the Monitor calls an API that has been hooked then
it'll be redirected to our ``trampoline`` right away (through a jump.)

The ``trampoline`` then goes through the following steps:

* Check whether we're already inside another hook through a
  thread-specific counter, and if so, ignore this hook (and all the following
  steps)::

    For example, system() calls CreateProcessInternalW() internally. However,
    as we already log the call to system() we do not have to log the call to
    CreateProcessInternalW(), as that would only give us duplicate data.

* Increase the hook counter::

    So that any further calls during this hook will not be logged.

* Save the Last Error::

    Our hook handler, of which we have one per function, may call any number
    of other API functions before calling the original function. In order to
    restore the Last Error right before calling the original function the
    trampoline saves the Last Error before calling the original hook handler.

* Save the original Return Address and replace it with one of ours::

    In order to do some cleanup at the very end of this API call (namely right
    before it returns to the caller) we save the last error just like the Last
    Error and replace it with one that points to the Assembly Cleanup snippet.

* Jump to the hook handler::

    At this point the hook has been setup as required and the Monitor jumps
    to our hook handler. From here on the hook handler can log and modify
    parameters as well as call the original function (or not call it at all,
    of course.)

.. _hook-asm-guide:

Hook Guide
^^^^^^^^^^

In most cases the hook handler will call the ``original`` function. This is
the point where the ``guide`` comes to play. The guide performs the following
steps:

* Restore the Last Error::

    At this point the Monitor restores the Last Error that had been saved by
    the trampoline. Optionally the hook handler is able to overwrite the saved
    Last Error before calling the original function, but in general this is
    not desired - this would be more useful when modifying parameters or
    return values.

* Save the Return Address and replace it with one of ours::

    Just as the Monitor saved the return address in the trampoline it does the
    same here. The guide replaces the return address with another address in
    the guide where execution will now go to after the original function
    returns.

* Execute the :ref:`hook-orig-stub`.

* Save the Last Error::

    We're now back in the guide right after having executed the original
    function. As the original function will likely have modified the Last
    Error, and we don't want the hook handler to mess it up, we save it again
    here.

* Fetch and jump to the Return Address::

    Finally the guide fetches the return address that was stored in the first
    part of the guide.

So basically the ``guide`` does not do much special. It's one and only purpose
is to ensure the Last Error is preserved correctly around the original
function. Execution now continues in the hook handler which will at some point
return after which we get into the ``Hook Cleanup``.

.. _hook-asm-clean:

Hook Cleanup
^^^^^^^^^^^^

Finally the ``hook cleanup`` snippet performs the following tasks:

* Restore the Last Error::

    Restore the Last Error that was saved in the guide. This is usually the
    Last Error as it was right after calling the original function.

* Decrease the hook counter::

    Having finished handling this function hook any further API calls should
    be logged again and thus we decrease the hook counter.

* Fetch and jump to the Original Return Address::

    This is the last step of our hooking mechanism - the cleanup snippet
    fetches the return address as stored by the trampoline and jumps to it.

.. _hook-orig-stub:

Original Function Stub
^^^^^^^^^^^^^^^^^^^^^^

As the first few bytes of the original function have been overwritten by our
hook we can't jump there anymore. Instead of calling the original function the
hook handler will actually call a stub which contains the original
instructions and a jump to the original function plus the offset to which
point the stub has covered the instructions::

    Let's assume that, like most WINAPI functions, the function prolog of a
    function X looks like the following.

        mov edi, edi
        push ebp
        mov ebp, esp
        sub esp, 24
        ...

    In this case the first three instructions represent five bytes together.
    Effectively this means that the function would look like the following
    after being hooked by the Monitor.

        jmp hook-trampoline
        sub esp, 24

    Now in order to call the original function the stub will look like the
    following.

        mov edi, edi
        push ebp
        mov ebp, esp
        jmp original_function+5

    And that's all..

.. _components-hook:

Hook Definitions
----------------

The Monitor features a unique and dynamic templating engine to `create API
hooks <hook-create>`. These API hooks are based on a simple to use text format
and are then translated into equivalent C code.

All of the API hooks can be found in the ``sigs/`` ("signatures") directory.

.. _components-py:

Python pre-processor script(s)
------------------------------

As of now there is only one Python script. This Python script takes all of
the signature files and translates them into a few files in the
``object/code/`` directory:

* hooks.c - hook ``code``.
* hooks.h - hook ``prototypes``.
* explain.c - strings related to ``logging`` hooked API calls.
* tables.c - table containing all ``hook entries`` to hook.

These generated C files are compiled and used by the C Framework as a sort of
data feed.
