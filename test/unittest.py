#!/usr/bin/env python
"""
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2015-2017 Cuckoo Foundation

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import copy
import os
import shlex
import sys

MODES = [
    'winxp',
    'win7',
    'win7x64',
]

MULTIPLE = {
    'CC': False,
    'CFLAGS': True,
    'INC': True,
    'OBJECTS': True,
    'MODES': True,
    'EXTENSION': False,
    'FREE': False,
    'FINISH': False,
    'PIPE': False,
}

DEFAULTS = {
    'CC86': 'i686-w64-mingw32-gcc',
    'CC64': 'x86_64-w64-mingw32-gcc',
    'CFLAGS': ['-std=c99', '-Wall', '-Werror', '-s', '-static'],
    'INC': ['-I', '../inc', '-I', '../objects/code', '-I', '../src/bson'],
    'OBJECTS': """pipe.o misc.o native.o memory.o utf8.o symbol.o ignore.o
        hooking.o unhook.o assembly.o log.o diffing.o sleep.o wmi.o exploit.o
        flags.o hooks.o config.o network.o iexplore.o sha1/sha1.o insns.o
        bson/bson.o bson/numbers.o bson/encoding.o disguise.o copy.o office.o
        ../src/capstone/capstone-%(arch)s.lib""".split(),
    'LDFLAGS': ['-lws2_32', '-lshlwapi', '-lole32'],
    'MODES': ['winxp', 'win7', 'win7x64'],
    'EXTENSION': 'exe',
    'FINISH': '',
    'FREE': '',
    'PIPE': '',
}

ALL = []

class Dict(dict):
    def __init__(self, value):
        dict.__init__(self, copy.deepcopy(value))

    def __getattr__(self, name):
        return dict.__getitem__(self, name)

def compile_file(fname, arch):
    kw = Dict(DEFAULTS)
    for line in open(fname, 'rb'):
        if not line.startswith('///'):
            continue

        key, value = line[3:].split('=', 1)
        if key.strip().endswith('+'):
            kw[key.rstrip('+').strip()] += shlex.split(value)
        elif MULTIPLE[key.strip()]:
            kw[key.strip()] = shlex.split(value)
        else:
            kw[key.strip()] = value.strip()

    for idx, value in enumerate(kw.OBJECTS):
        kw.OBJECTS[idx] = value = value % dict(arch=arch)
        if os.path.exists(value):
            continue

        path = os.path.join('..', 'objects', arch, 'src', value)
        if os.path.exists(path):
            kw.OBJECTS[idx] = path
            continue

        path = os.path.join('..', 'objects', arch, 'code', value)
        if os.path.exists(path):
            kw.OBJECTS[idx] = path
            continue

    # Write extra configuration to the config.yml file.
    with open(os.path.join(arch, "config.yml"), "a+b") as f:
        if kw.FINISH == 'yes' or kw.PIPE == 'yes' or kw.FREE == 'yes':
            f.write("%s:\n" % fname[:-2])
            f.write("  options:\n")
            if kw.FINISH == 'yes':
                f.write('    "unittest.finish": "1"\n')
            if kw.PIPE == 'yes':
                f.write('    "pipe": "cuckoo"\n')
            if kw.FREE == 'yes':
                f.write('    "free": "yes"\n')
            f.write('\n')

    output_exe = os.path.join(arch, fname.replace('.c', '.%s' % kw.EXTENSION))

    compiler = kw.CC86 if arch == 'x86' else kw.CC64
    files = ' '.join(kw.OBJECTS)
    args = ' '.join(kw.CFLAGS + kw.LDFLAGS + kw.INC)
    ALL.append(output_exe)

    return [
        '%s: %s %s' % (output_exe, fname, files),
        '\t%s -o %s %s %s %s' % (compiler, output_exe, fname, files, args),
        '',
    ]

if __name__ == '__main__':
    curdir = os.path.abspath(os.path.dirname(__file__))

    lines = []
    for fname in os.listdir(curdir):
        if not fname.endswith('.c'):
            continue

        lines += compile_file(fname, 'x86')
        lines += compile_file(fname, 'x64')

    with open(os.path.join(curdir, 'Makefile'), 'wb') as f:
        f.write('all: %s\n' % ' '.join(ALL))
        f.write('clean:\n\trm -f %s\n\n' % ' '.join(ALL))
        f.write('\n'.join(lines))
