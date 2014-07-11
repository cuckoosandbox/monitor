import docutils.nodes
import docutils.utils
import docutils.parsers.rst
import jinja2.environment
import os.path


class DefitionProcessor(object):
    def __init__(self, sigs, template, path):
        self.sigs = sigs
        self.path = path
        self.templ = jinja2.environment.Template(open(template, 'rb').read())

    def parser_settings(self):
        components = docutils.parsers.rst.Parser,
        settings = docutils.frontend.OptionParser(components=components)
        return settings.get_default_values()

    def read_document(self):
        doc = docutils.utils.new_document(os.path.basename(self.sigs),
                                          self.parser_settings())
        parser = docutils.parsers.rst.Parser()
        parser.parse(open(self.sigs, 'rb').read(), doc)
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

    def header(self, f):
        print>>f, '#include <stdio.h>'
        print>>f, '#include <windows.h>'
        print>>f

    def footer(self, f):
        pass

    def create(self, hooks):
        f = open(self.path, 'wb')
        self.header(f)

        types = dict(
            HANDLE='p',
            PHANDLE='P',
            POBJECT_ATTRIBUTES='O',
            PLARGE_INTEGER='Q',
            ULONG='l',
        )

        for hook in hooks:
            print>>f, self.templ.render(hook=hook, types=types)
            print>>f

        self.footer(f)

    def process(self):
        self.create(self.normalize(self.read_document()))

if __name__ == '__main__':
    dp = DefitionProcessor('data/sigs.rst', 'data/hooks.jinja2', '_hooks.c')
    dp.process()
