#!/usr/bin/env python

import copy
import os
import shlex
import subprocess

MULTIPLE = {
    'CC': False,
    'CFLAGS': True,
    'INC': True,
    'OBJECTS': True,
}

DEFAULTS = {
    'CC': 'i686-w64-mingw32-gcc',
    'CFLAGS': ['-std=c99', '-Wall', '-Werror', '-s'],
    'INC': ['-I', '../inc', '-I', '../objects/code'],
    'OBJECTS': """pipe.o misc.o native.o memory.o utf8.o symbol.o ignore.o
        hooking.o unhook.o assembly.o log.o diffing.o sleep.o dropped.o
        flags.o hooks.o config.o
        bson/bson.o bson/numbers.o bson/encoding.o
        ../src/capstone/capstone-x86.lib""".split(),
    'LDFLAGS': ['-lws2_32', '-lshlwapi', '-lole32'],
}

class Dict(dict):
    def __init__(self, value):
        dict.__init__(self, copy.deepcopy(value))

    def __getattr__(self, name):
        return dict.__getitem__(self, name)

def process_file(fname):
    output_exe = fname.replace('.c', '.exe')

    kw = Dict(DEFAULTS)
    for line in open(fname, 'rb'):
        if not line.startswith('///'):
            continue

        key, value = line[3:].split('=', 1)
        if key.strip().endswith('+'):
            kw[key.strip().rstrip('+')] += shlex.split(value)
        elif MULTIPLE[key.strip()]:
            kw[key.strip()] = shlex.split(value)
        else:
            kw[key.strip()] = value.strip()

    for idx, value in enumerate(kw.OBJECTS):
        if os.path.exists(value):
            continue

        path = os.path.join('..', 'objects', 'x86', 'src', value)
        if os.path.exists(path):
            kw.OBJECTS[idx] = path
            continue

        path = os.path.join('..', 'objects', 'x86', 'code', value)
        if os.path.exists(path):
            kw.OBJECTS[idx] = path
            continue

    args = [kw.CC, '-o', output_exe, fname] + kw.CFLAGS + kw.INC + \
        kw.OBJECTS + kw.LDFLAGS
    subprocess.check_call(args)

if __name__ == '__main__':
    curdir = os.path.abspath(os.path.dirname(__file__))
    for fname in os.listdir(curdir):
        if fname.startswith('test-') and fname.endswith('.c'):
            process_file(fname)
