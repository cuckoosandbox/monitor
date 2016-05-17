#!/bin/sh

# Don't forget to "make clean" if this is the first time you run
# make with the DEBUG flag set. Otherwise source code that depends
# on the DEBUG flag might already have been compiled.
DEBUG=1 DEBUG_HEAPCORRUPTION=1 make
