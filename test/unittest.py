#!/usr/bin/env python
"""
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Foundation

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

import argparse
import copy
import os
import shlex
import subprocess

MULTIPLE = {
    'CC': False,
    'CFLAGS': True,
    'INC': True,
    'OBJECTS': True,
    'SUBMIT': False,
    'OPTIONS': True,
    'MODES': True,
    'EXTENSION': False,
}

DEFAULTS = {
    'CC86': 'i686-w64-mingw32-gcc',
    'CC64': 'x86_64-w64-mingw32-gcc',
    'CFLAGS': ['-std=c99', '-Wall', '-Werror', '-s'],
    'INC': ['-I', '../inc', '-I', '../objects/code'],
    'OBJECTS': """pipe.o misc.o native.o memory.o utf8.o symbol.o ignore.o
        hooking.o unhook.o assembly.o log.o diffing.o sleep.o
        flags.o hooks.o config.o
        bson/bson.o bson/numbers.o bson/encoding.o
        ../src/capstone/capstone-%(arch)s.lib""".split(),
    'LDFLAGS': ['-lws2_32', '-lshlwapi', '-lole32'],
    'SUBMIT': '../../cuckoo/utils/submit.py',
    'OPTIONS': [],
    'MODES': ['winxp', 'win7', 'win7x64'],
    'EXTENSION': 'exe',
}

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

    output_exe = fname.replace('.c', '-%s.%s' % (arch, kw.EXTENSION))

    compiler = kw.CC86 if arch == 'x86' else kw.CC64
    args = [compiler, '-o', output_exe, fname]
    args += kw.CFLAGS + kw.INC + kw.OBJECTS + kw.LDFLAGS
    subprocess.check_call(args)
    return kw, output_exe

def submit_file(kw, fname, tags=None):
    args = [kw.SUBMIT, fname]

    for row in kw.OPTIONS:
        args += ['--options', row]

    if tags:
        args += ['--tags', tags]

    subprocess.check_call(args)

def process_file(fname, modes):
    kw, outfile = compile_file(fname, 'x86')

    if 'winxp' in modes and 'winxp' in kw.MODES:
        submit_file(kw, outfile, tags='winxp')

    if 'win7' in modes and 'win7' in kw.MODES:
        submit_file(kw, outfile, tags='win7')

    if 'win7x64' in modes and 'win7x64' in kw.MODES:
        kw, outfile = compile_file(fname, 'x64')
        submit_file(kw, outfile, tags='win7x64')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--modes', type=str, default='winxp,win7,win7x64', help='Modes to process.')
    args = parser.parse_args()

    modes = []
    for mode in args.modes.split(','):
        if mode.strip():
            modes.append(mode.strip())

    curdir = os.path.abspath(os.path.dirname(__file__))
    for fname in os.listdir(curdir):
        if fname.startswith('test-') and fname.endswith('.c'):
            process_file(fname, modes=modes)
