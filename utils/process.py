#!/usr/bin/env python
"""
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2014-2018 Cuckoo Foundation

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
import docutils.nodes
import docutils.utils
import docutils.parsers.rst
import jinja2
import json
import os
import sys
import yaml

class DefinitionProcessor(object):
    def __init__(self, data_dir):
        fs_loader = jinja2.FileSystemLoader(data_dir)
        self.templ_env = jinja2.Environment(loader=fs_loader)

    def parser_settings(self):
        components = docutils.parsers.rst.Parser,
        settings = docutils.frontend.OptionParser(components=components)
        return settings.get_default_values()

    def read_document(self, sig):
        doc = docutils.utils.new_document(os.path.basename(sig),
                                          self.parser_settings())
        parser = docutils.parsers.rst.Parser()
        parser.parse(open(sig, 'rb').read(), doc)
        return parser

    def template(self, name):
        return self.templ_env.get_template('%s.jinja2' % name)

    def render(self, template, path, **kwargs):
        with open(path, 'wb') as f:
            f.write(self.template(template).render(**kwargs))


class SignatureProcessor(object):
    CALLING_CONVENTIONS = {
        'WINAPI': 'WINAPI',
        '__cdecl': '',
        '__thiscall': '__thiscall',
    }

    def __init__(self, data_dir, out_dir, sig_dirpath, flags, insns):
        self.data_dir = data_dir
        self.flags = flags
        self.insns = insns

        base_sigs_path = os.path.join(data_dir, 'base-sigs.json')
        types_path = os.path.join(data_dir, 'types.conf')
        is_success_path = os.path.join(data_dir, 'is-success.conf')
        dereference_path = os.path.join(data_dir, 'dereference.conf')

        self.hooks_c = os.path.join(out_dir, 'hooks.c')
        self.hooks_h = os.path.join(out_dir, 'hooks.h')
        self.hook_info_h = os.path.join(out_dir, 'hook-info.h')

        self.sig_dirpath = sig_dirpath

        self.types = {}
        for line in open(types_path, 'rb'):
            key, value = line.split('=', 1)
            self.types[key.strip()] = value.strip()

        self.is_success = {}
        for line in open(is_success_path, 'rb'):
            key, value = line.split('=', 1)
            self.is_success[key.strip()] = value.strip()

        self.dereference = {}
        for line in open(dereference_path, 'rb'):
            key, value = line.split('=', 1)
            self.dereference[key.strip()] = value.strip()

        self.base_sigs = []
        for entry in json.load(open(base_sigs_path, 'rb')):
            entry['is_hook'] = False
            entry['signature']['special'] = False
            for param in entry['parameters']:
                param['alias'] = param['argname']
                param['log'] = True

            self.base_sigs.append(entry)

    def _parse_signature(self, text):
        ret = {}
        for line in text.split('\n'):
            if not line.startswith('*'):
                raise Exception('Every line of the signature should start '
                                'with an asterisks: %r.' % line)

            key, value = line[1:].split(':', 1)
            ret[key.strip().lower().replace(' ', '_')] = value.strip()

        return ret

    def _parse_parameters(self, text):
        ret = []
        for line in text.split('\n'):
            if not line.startswith('*'):
                raise Exception('Parameter declaration should have at least '
                                'one asterisks: %r.' % line)

            line = line[1:].strip()

            # We have to log this argument.
            log = False
            if line.startswith('*'):
                log = True
                line = line[1:].strip()

            # Certain keywords are to be ignored.
            argtype = []
            while line.startswith(('const ', 'CONST ', 'struct ')):
                argtype.append(line.split(' ', 1)[0])
                line = line.split(' ', 1)[1].strip()

            if line.count(' ') == 1:
                argtype.append(line.split()[0])
                alias = argname = line.split()[1]
            elif line.count(' ') == 2:
                argtype.append(line.split()[0])
                argname, alias = line.split()[1:]
            else:
                raise Exception('Incorrect whitespace count in parameter '
                                'line: %r.' % line)

            alias = alias.replace('*', '').replace('[]', '').strip()

            while argname.startswith('*'):
                argname = argname[1:].strip()
                if argtype[-1].startswith('*'):
                    argtype[-1] += '*'
                else:
                    argtype.append('*')

            if argname.endswith('[]'):
                argname = argname[:-2].strip()
                if argtype[-1] == '*':
                    argtype[-1] += '*'
                else:
                    argtype.append('*')

            if argname.endswith(','):
                raise Exception('Parameter line ends with a comma: %s' % line)

            ret.append(dict(argtype=' '.join(argtype).strip(),
                            argname=argname.strip(),
                            alias=alias, log=log))
        return ret

    def _parse_flags(self, text):
        # Don't parse flags if they're not provided.
        if not self.flags:
            return []

        ret = []
        for line in text.split('\n'):
            line = line.split()
            if len(line) == 1:
                ret.append(dict(name=line[0]))
            elif len(line) == 2:
                ret.append(dict(name=line[0], arg=line[1], argtype=None))
            elif len(line) == 3:
                ret.append(dict(name=line[0], arg=line[1], argtype=line[2]))
        return ret

    def _parse_interesting(self, text):
        ret = []
        for line in text.split('\n'):
            if line.startswith('*'):
                raise Exception('Do not use asterisks in Interesting blocks.')

            argtype, argvalue = line.strip().split(' ', 1)
            ret.append(dict(argtype=argtype, argvalue=argvalue))
        return ret

    def _parse_ensure(self, text):
        ret = []
        for line in text.split('\n'):
            if line.startswith('*'):
                raise Exception('Do not use asterisks in Ensure blocks.')

            ret.append(line)
        return ret

    def _parse_pre(self, text):
        return text.split('\n')

    def _parse_prelog(self, text):
        argtype, argname, parameter = text.split(' ', 2)
        if argtype != 'b' and argtype != '!b':
            raise Exception('Prelog parameter must be a buffer.')

        length, buffer = parameter.split(',')
        return dict(argtype=argtype, argname=argname,
                    length=length.strip(), buffer=buffer.strip())

    def _parse_middle(self, text):
        return text.split('\n')

    def _parse_logging(self, text):
        ret = []
        for line in text.split('\n'):
            if line.startswith('*'):
                line = line[1:].strip()

            argtype, argname, argvalue = line.strip().split(' ', 2)
            ret.append(dict(argtype=argtype,
                            argname=argname,
                            argvalue=argvalue))
        return ret

    def _parse_post(self, text):
        return text.split('\n')

    def _parse_replace(self, text):
        ret = {}
        for line in text.split('\n'):
            key, value = line.split(None, 1)
            ret[key.strip()] = value.strip()
        return ret

    def _parse_paragraph(self, paragraph, literal_block):
        if not isinstance(paragraph, docutils.nodes.paragraph):
            raise Exception('Node must be a paragraph.')

        if not isinstance(literal_block, docutils.nodes.literal_block):
            raise Exception('Child node must be a literal block.')

        key = paragraph.astext().replace(':', '').lower()
        if not hasattr(self, '_parse_' + key):
            raise Exception('No parser known for the %r section.' % key)

        return key, getattr(self, '_parse_' + key)(literal_block.astext())

    def _prevent_overwrite(self, key, value, global_values):
        if key != 'signature' or key not in global_values:
            return

        prevents = dict(
            library='Library',
            calling_convention='Calling convention',
            category='Category',
            return_value='Return value',
        )

        for k, v in prevents.items():
            if k in global_values[key] and k in value:
                raise Exception('Please do not overwrite %r values.' % v)

    def normalize(self, doc):
        global_values, start = {}, 0

        # Empty signatures file?
        if not doc.document.children:
            return

        while isinstance(doc.document.children[start],
                         docutils.nodes.paragraph):
            try:
                children = doc.document.children
                key, value = self._parse_paragraph(children[start],
                                                   children[start+1])
            except Exception as e:
                raise Exception('Error parsing global node: %s' % e.message)

            global_values[key] = value
            start += 2

        for entry in doc.document.ids.values():
            if not isinstance(entry.children[0], docutils.nodes.title):
                raise Exception('Node must be a title.')

            apiname = entry.children[0].astext()
            children = entry.children

            if apiname.startswith('_'):
                print>>sys.stderr, \
                    'Skipping ignored API Signature:', apiname[1:]
                continue

            row = copy.deepcopy(global_values)

            row['apiname'] = apiname

            for x in xrange(1, len(children), 2):
                try:
                    key, value = self._parse_paragraph(children[x],
                                                       children[x+1])

                    if key in row:
                        self._prevent_overwrite(key, value, global_values)
                        row[key].update(value)
                    else:
                        row[key] = value

                except Exception as e:
                    raise Exception('Error parsing node of api %r: %s' %
                                    (apiname, e.message))

            row['library'] = row['signature']['library'].replace('.', '_')

            # By default hooks are not "special". Special hooks are those
            # hooks that are executed also when already inside another hook.
            # Note that it doesn't really matter what value is specified for
            # "special" in the signature, as long as it is set.
            row['signature']['special'] = 'special' in row['signature']

            # Check whether there is a return value present.
            if 'return_value' not in row['signature']:
                raise Exception('No return value present for %r.' %
                                row['apiname'])

            # If no is_success handler has been defined then use one based on
            # the return value. (This is the default behavior.)
            if 'is_success' not in row['signature']:
                retval = row['signature']['return_value']
                if retval not in self.is_success:
                    raise Exception('Unknown return_value %r for api %r.' %
                                    (retval, row['apiname']))

                row['signature']['is_success'] = self.is_success[retval]

            # Check the calling convention.
            cconv = row['signature'].get('calling_convention')
            if cconv not in self.CALLING_CONVENTIONS:
                raise Exception(
                    'Calling convention of %r must be WINAPI, __cdecl, or '
                    '__thiscall.' % row['apiname']
                )

            row['signature']['calling_convention'] = \
                self.CALLING_CONVENTIONS[cconv]

            # Check any defined callback functions.
            if 'callback' in row['signature']:
                row['signature']['callback'] = \
                    row['signature']['callback'].split()
            else:
                row['signature']['callback'] = []

            # Convert the modes to their macro representatives.
            if 'mode' in row['signature']:
                modes = []
                for mode in row['signature']['mode'].split():
                    modes.append('HOOK_MODE_%s' % mode.upper())
                row['signature']['mode'] = '|'.join(modes)

            # Check the types of each parameter.
            ensure = {}
            for arg in row.get('parameters', []):
                if arg['log'] and arg['argtype'] not in self.types:
                    raise Exception('Unknown argtype %r in %s, please add it '
                                    'to data/types.conf.' % (arg['argtype'],
                                                             row['apiname']))

                # Check whether we have to "ensure" this parameter. That is,
                # it's a pointer and we'd like to have its contents after the
                # original function call even if it's originally specified as
                # a null pointer.
                if 'ensure' in row and arg['argname'] in row['ensure']:
                    if arg['argtype'] not in self.dereference:
                        raise Exception(
                            'No dereference definition available for '
                            'argument type %r. Please add it to '
                            'data/dereference.conf' % arg['argtype'])

                    ensure[arg['argname']] = self.dereference[arg['argtype']]

            # Dictionary with the dereferenced types for each parameter.
            row['ensure'] = ensure

            # Check whether every flag alias exists.
            for idx, flag in enumerate(row.get('flags', [])):
                for arg in row.get('parameters', []):
                    if flag['name'] == arg['alias']:
                        flag['arg'] = arg['argname']
                        flag['argtype'] = arg['argtype']
                        break

                if 'arg' not in flag:
                    raise Exception('Alias %r not found in %r!' % (
                                    flag, row['apiname']))

                flagname = '%s_%s' % (row['apiname'], flag['arg'])
                if flagname not in self.flags:
                    if flag['argtype'] not in self.flags:
                        raise Exception('Flag %r of %r (%r) is unknown!' % (
                            flag['name'], row['apiname'], flagname))

                    flag['flagname'] = flag['argtype']
                else:
                    flag['flagname'] = flagname

            # Resolve any aliases in Interesting blocks.
            for interesting in row.get('interesting', []):
                for arg in row.get('parameters', []):
                    if interesting['argvalue'] == arg['alias']:
                        interesting['argvalue'] = arg['argname']
                        break

            row['signature']['interesting'] = \
                'interesting' in row['signature']

            yield row

    def process(self):
        self.dp = DefinitionProcessor(self.data_dir)

        # Fetch all available signatures.
        sigs = []
        for sig_file in os.listdir(self.sig_dirpath):
            if not sig_file.endswith('.rst'):
                continue

            sig_path = os.path.join(self.sig_dirpath, sig_file)
            for sig in self.normalize(self.dp.read_document(sig_path)):
                sig['is_hook'] = True
                sigs.append(sig)

        # Get all hooked API functions per library.
        siglibs = {}
        for sig in sigs:
            library = sig['signature']['library']
            if library not in siglibs:
                siglibs[library] = []

            siglibs[library].append(sig)

        # Create a list of all signatures in a sorted manner.
        sigs = self.base_sigs[:]
        for library in sorted(siglibs.keys()):
            sigs.extend(sorted(siglibs[library], key=lambda x: x['apiname']))

        # Add each instruction-level hook.
        last = None
        for insn in self.insns.methods:
            logging = []

            # We take the logging of the first entry.
            for param in insn["entries"][0]["logging"]:
                logging.append({
                    "argtype": param["type"],
                    "argname": param["name"],
                })

            sigs.append({
                "library": insn["module_clean"],
                "apiname": insn["funcname"],
                "ignore": last == insn["funcname"],
                "is_insn": True,
                "is_hook": True,
                "signature": {
                    "category": insn["category"],
                    "library": insn["module"],
                    "special": False,
                    "mode": "HOOK_MODE_%s" % insn["mode"].upper(),
                    "callback": "module",
                },
                "logging": logging,
            })
            last = insn["funcname"]

        # Assign hook indices accordingly (in a sorted manner).
        for idx, sig in enumerate(sigs):
            sig['index'] = idx

        self.sigs = sigs

    def render(self, apis, debug=False):
        # If set, only hook the specified functions.
        for sig in self.sigs:
            if apis and sig['apiname'] not in apis and \
                    not sig['apiname'].startswith('__'):
                sig['ignore'] = True

        self.dp.render('hook-header', self.hooks_h, sigs=self.sigs)
        self.dp.render('hook-source', self.hooks_c,
                       sigs=self.sigs, types=self.types, debug=debug)
        self.dp.render('hook-info-header', self.hook_info_h,
                       sigs=self.sigs, first_hook=len(self.base_sigs))

    def list_categories(self):
        categories = {}
        for sig in self.sigs:
            category = sig['signature']['category']
            if category not in categories:
                categories[category] = None
                print category

    def list_apis(self):
        for sig in self.sigs:
            print sig['signature']['category'], sig['apiname']

class FlagsProcessor(object):
    def __init__(self, data_dir, output_directory):
        self.data_dir = data_dir
        self.flags = {}

        self.flags_c = os.path.join(output_directory, 'flags.c')
        self.flags_h = os.path.join(output_directory, 'flags.h')

    def _parse_enum(self, text):
        return text.split()

    def _parse_value(self, text):
        return text.split()

    def _parse_inherits(self, text):
        return text.split()

    def _parse_paragraph(self, paragraph, literal_block):
        if not isinstance(paragraph, docutils.nodes.paragraph):
            raise Exception('Node must be a paragraph.')

        if not isinstance(literal_block, docutils.nodes.literal_block):
            raise Exception('Child node must be a literal block.')

        key = paragraph.astext().replace(':', '').lower()
        if not hasattr(self, '_parse_' + key):
            raise Exception('No parser known for the %r section.' % key)

        return key, getattr(self, '_parse_' + key)(literal_block.astext())

    def normalize(self, doc):
        # Empty flags file?
        if not doc.document.children:
            return

        for entry in doc.document.ids.values():
            if not isinstance(entry.children[0], docutils.nodes.title):
                raise Exception('Node must be a title.')

            flagname = entry.children[0].astext()
            children = entry.children

            row = dict(name=flagname, value=[], enum=[])

            for x in xrange(1, len(children), 2):
                try:
                    key, value = self._parse_paragraph(children[x],
                                                       children[x+1])
                    row[key] = value

                except Exception as e:
                    raise Exception('Error parsing node of flag %r: %s' %
                                    (flagname, e.message))

            yield row

    def process(self, dirpath):
        dp = DefinitionProcessor(self.data_dir)

        if not dirpath:
            return

        # Fetch all available flags.
        for flag_file in os.listdir(dirpath):
            if not flag_file.endswith('.rst'):
                continue

            flag_path = os.path.join(dirpath, flag_file)
            for flag in self.normalize(dp.read_document(flag_path)):
                self.flags[flag['name']] = flag

        # Handle inheritance.
        for flag in self.flags.values():
            # TODO Use proper inheritance without duplication,
            # see also the todo list.
            for inherit in flag.get('inherits', []):
                flag['enum'] += self.flags[inherit]['enum']
                flag['value'] += self.flags[inherit]['value']

    def write(self):
        dp = DefinitionProcessor(self.data_dir)

        dp.render('flags-source', self.flags_c, flags=self.flags)
        dp.render('flags-header', self.flags_h, flags=self.flags)

class InsnProcess(object):
    registers = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ]

    def __init__(self, outfile, insnfiles):
        self.outfile = outfile
        self.insnfiles = insnfiles

    def parse_arguments(self, e):
        r = []

        if e.get("register"):
            r.append(e["register"])

        if e.get("registers"):
            r.extend(e["registers"].split())

        if "stack" in e:
            for idx, offset in enumerate(str(e["stack"]).split()):
                r.append(("stk%d" % idx, int(offset)))

        return r

    def parse_logging(self, l):
        if not l:
            return []

        if isinstance(l, basestring):
            l = [l]

        r = []
        for x in l:
            type_, name, value = x.split(None, 2)
            r.append({
                "type": type_,
                "name": name,
                "value": value,
            })
        return r

    def make_signature(self, arguments):
        args, signature = [], []
        for idx, arg in enumerate(arguments):
            value = None
            if isinstance(arg, tuple):
                arg, value = arg

            args.append(arg)
            if arg.lower() in self.registers:
                signature.append(
                    "(HOOK_INSN_%s << %d)" % (arg.upper(), (3 - idx) * 8)
                )
            elif arg.lower().startswith("stk"):
                signature.append(
                    "(HOOK_INSN_STK(%s) << %s)" % (
                        value, (3 - idx) * 8
                    )
                )
            else:
                raise

        return args, " | ".join(signature)

    def process(self):
        methods = []
        for filepath in self.insnfiles:
            doc = yaml.load(open(filepath, "rb"))
            if not doc:
                continue
            glob = doc.pop("global", {})

            for funcname, info in doc.items():
                idx, entries = 0, []
                module = info.get("module", glob.get("module"))
                category = info.get("category", glob.get("category"))
                mode = info.get("mode", glob.get("mode", "all"))
                for timestamp, entry in info["offsets"].items():
                    arguments = self.parse_arguments(entry)
                    logging = self.parse_logging(entry.get("logging"))

                    arguments, signature = self.make_signature(arguments)

                    entries.append({
                        "index": idx,
                        "module": module,
                        "funcname": funcname,
                        "category": category,
                        "mode": mode,
                        "timestamp": timestamp,
                        "offset": entry.get("offset"),
                        "arguments": arguments,
                        "signature": signature,
                        "logging": logging,
                        "pre": entry.get("pre"),
                        "bitmode": entry.get("bitmode", 32),
                    })
                    idx += 1

                methods.append({
                    "module": module,
                    "module_clean": module.replace(".", "_"),
                    "funcname": funcname,
                    "category": category,
                    "mode": mode,
                    "init": info.get("init"),
                    "entries": entries,
                })

        modules = {}
        for method in methods:
            if method["module"] not in modules:
                modules[method["module"]] = {
                    "module": method["module"],
                    "clean": method["module"].replace(".", "_"),
                    "init": method["init"],
                    "methods": [],
                }

            modules[method["module"]]["methods"].append(method)

        self.methods = methods
        self.modules = modules

    def write(self, apis):
        content = self.render("insn", apis, {
            "methods": self.methods,
            "modules": self.modules,
        })
        open(self.outfile, "wb").write(content)

    def render(self, docname, apis, variables, dirpath="data/"):
        for method in self.methods:
            if apis and method["funcname"] not in apis:
                method["ignore"] = True

        fs_loader = jinja2.FileSystemLoader(dirpath)
        templ_env = jinja2.Environment(loader=fs_loader)
        templ = templ_env.get_template("%s.jinja2" % docname)
        return templ.render(**variables)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', type=str, help='Action to perform.')
    parser.add_argument('data_directory', type=str, nargs='?', default='data/', help='Path to data directory.')
    parser.add_argument('output_directory', type=str, nargs='?', default='objects/code/', help='Output directory.')
    parser.add_argument('signatures_directory', type=str, nargs='?', default='sigs/', help='Signature directory.')
    parser.add_argument('flags_directory', type=str, nargs='?', default='flags/', help='Flags directory.')
    parser.add_argument('-a', '--apis', type=str, help='If set, only hook these functions.')
    args = parser.parse_args()

    insnfiles = []
    for filename in os.listdir("insn"):
        if filename.endswith((".yml", ".yaml")):
            insnfiles.append(os.path.join("insn", filename))

    ip = InsnProcess("objects/code/insns.c", insnfiles)
    ip.process()

    fp = FlagsProcessor(args.data_directory, args.output_directory)
    fp.process(args.flags_directory)

    dp = SignatureProcessor(args.data_directory, args.output_directory,
                            args.signatures_directory, fp.flags.keys(), ip)
    dp.process()

    apis = []
    if args.apis:
        for api in args.apis.split(','):
            if api.strip():
                apis.append(api.strip())

    if args.action == 'release':
        fp.write()
        dp.render(apis)
        ip.write(apis)
    elif args.action == 'debug':
        fp.write()
        dp.render(apis, debug=True)
        ip.write(apis)
    elif args.action == 'list-categories':
        dp.list_categories()
    elif args.action == 'list-apis':
        dp.list_apis()
    else:
        sys.exit('Invalid action: %r' % args.action)
