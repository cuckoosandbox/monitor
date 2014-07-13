import docutils.nodes
import docutils.utils
import docutils.parsers.rst
from jinja2.environment import Template
import os.path
import sys


class DefitionProcessor(object):
    def __init__(self, header, source, sigs, data_dir):
        self.header = header
        self.source = source
        self.sigs = sigs

        templ_source_path = os.path.join(data_dir, 'source.jinja2')
        templ_header_path = os.path.join(data_dir, 'header.jinja2')
        types_path = os.path.join(data_dir, 'types.conf')

        self.templ_source = Template(open(templ_source_path, 'rb').read())
        self.templ_header = Template(open(templ_header_path, 'rb').read())

        self.types = {}
        for line in open(types_path, 'rb'):
            key, value = line.split('=', 1)
            self.types[key.strip()] = value.strip()

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

    def _parse_signature(self, text):
        ret = {}
        for line in text.split('\n'):
            if line.startswith('*'):
                line = line[1:]

            key, value = line.split(':')
            ret[key.strip().lower().replace(' ', '_')] = value.strip()

        return ret

    def _parse_parameters(self, text):
        ret = []
        for line in text.split('\n'):
            if line.startswith('*'):
                line = line[1:].strip()

            # We have to log this argument.
            log = False
            if line.startswith('*'):
                log = True
                line = line[1:].strip()

            if line.count(' ') == 1:
                argtype, argname = line.split()
                alias = argname
            elif line.count(' ') == 2:
                argtype, argname, alias = line.split()
            else:
                raise

            if argname.endswith(','):
                raise

            ret.append(dict(argtype=argtype.strip(),
                            argname=argname.strip(),
                            alias=alias, log=log))
        return ret

    def _parse_pre(self, text):
        return text.split('\n')

    def _parse_post(self, text):
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

    def normalize(self, doc):
        ret = []
        for index in doc.document.ids:
            entry = doc.document.ids[index]
            apiname = entry.children[0].astext()
            children = entry.children

            row = dict(apiname=apiname)

            for x in xrange(1, len(children), 2):
                if not isinstance(children[x], docutils.nodes.paragraph):
                    raise

                if not isinstance(children[x+1], docutils.nodes.literal_block):
                    raise

                key = children[x].astext().replace(':', '').lower()
                if not hasattr(self, '_parse_' + key):
                    raise

                row[key] = \
                    getattr(self, '_parse_' + key)(children[x+1].astext())

            ret.append(row)
        return ret

    def initial_header(self, f):
        print>>f, '#ifndef MONITOR_HOOKS_H_'
        print>>f, '#define MONITOR_HOOKS_H_'
        print>>f

    def ending_header(self, f):
        print>>f, '#endif'

    def initial_source(self, f):
        print>>f, '#include <stdio.h>'
        print>>f, '#include <windows.h>'
        print>>f

    def ending_source(self, f):
        pass

    def write(self, h, s, hooks):
        for hook in hooks:
            print>>h, self.templ_header.render(hook=hook, types=self.types)
            print>>h

            print>>s, self.templ_source.render(hook=hook, types=self.types)
            print>>s

    def process(self):
        h = open(self.header, 'wb')
        s = open(self.source, 'wb')

        self.initial_header(h)
        self.initial_source(s)

        for sig in self.sigs:
            self.write(h, s, self.normalize(self.read_document(sig)))

        self.ending_header(h)
        self.ending_source(s)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage: python %s <out.h> <out.c> <sigs.rst...>' % sys.argv[0]
        exit(1)

    dp = DefitionProcessor(sys.argv[1], sys.argv[2], sys.argv[3:],
                           data_dir='data')
    dp.process()
