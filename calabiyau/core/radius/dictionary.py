# -*- coding: utf-8 -*-
# Copyright (c) 2019-2020 Christiaan Frans Rademan <chris@fwiw.co.za>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holders nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.

import os
import copy
import bidict

from luxon import GetLogger
from luxon.utils.text import split
from luxon.utils.pkg import Module

from calabiyau.exceptions import ParseError
from calabiyau.core.radius.attribute import Attribute
from calabiyau.core.utils.radius import encode, ENCODERS

log = GetLogger(__name__)


class Node(object):
    __slots__ = ('name', 'lines', 'current', 'length', 'dir')

    def __init__(self, fd, name, parentdir):
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def next(self):
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class PackageLexer(object):
    __slots__ = ('_package', '_dictionary', 'stack')

    def __init__(self, dictionary):
        self.stack = []
        dictionary = dictionary.strip('/')
        package, dictionary = split(dictionary, '/')
        self._package = Module(package)
        self._dictionary = '/' + dictionary
        self._read_node(self._dictionary)

    def _read_node(self, dictionary):
        node = None
        parentdir = self._dictionary.lstrip('/').split('/')
        parentdir = '/'.join(parentdir[0:-1])
        if isinstance(dictionary, str):
            fname = None
            if os.path.isabs(dictionary):
                fname = dictionary
            else:
                fname = os.path.join(parentdir, dictionary)
            fd = self._package.file(fname)
            node = Node(fd, dictionary, parentdir)
            fd.close()
        else:
            node = Node(dictionary, '', parentdir)
        self.stack.append(node)

    def _cur_dir(self):
        if self.stack:
            return self.stack[-1].dir
        else:
            return self._dictionary

    def _get_include(self, line):
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() == '$INCLUDE':
            return " ".join(tokens[1:])
        else:
            return None

    def line(self):
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def file(self):
        if self.stack:
            return self.stack[-1].name
        else:
            return ''

    def __iter__(self):
        return self

    def __next__(self):
        while self.stack:
            line = self.stack[-1].next()
            if line is None:
                self.stack.pop()
            else:
                line = line.decode('utf-8')
                inc = self._get_include(line)
                if inc:
                    self._read_node(inc)
                else:
                    return line
        raise StopIteration


class FileLexer(object):
    __slots__ = ('stack')

    def __init__(self, dictionary):
        self.stack = []
        self._read_node(dictionary)

    def _read_node(self, dictionary):
        node = None
        parentdir = self._cur_dir()
        if isinstance(dictionary, str):
            fname = None
            if os.path.isabs(dictionary):
                fname = dictionary
            else:
                fname = os.path.join(parentdir, dictionary)
            fd = open(fname, "rt")
            node = Node(fd, dictionary, parentdir)
            fd.close()
        else:
            node = Node(dictionary, '', parentdir)
        self.stack.append(node)

    def _cur_dir(self):
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def _get_include(self, line):
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() == '$INCLUDE':
            return " ".join(tokens[1:])
        else:
            return None

    def line(self):
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def file(self):
        if self.stack:
            return self.stack[-1].name
        else:
            return ''

    def __iter__(self):
        return self

    def __next__(self):
        while self.stack:
            line = self.stack[-1].next()
            if line is None:
                self.stack.pop()
            else:
                inc = self._get_include(line)
                if inc:
                    self._read_node(inc)
                else:
                    return line
        raise StopIteration


class Dictionary(object):
    __slots__ = ('vendors', 'attrindex', 'attributes', 'defer_parse')

    def __init__(self):
        self.vendors = bidict.bidict()
        self.vendors[''] = 0
        self.attrindex = bidict.bidict()
        self.attributes = {}
        self.defer_parse = []

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    def _parse_attribute(self, state, tokens):
        if not len(tokens) in [4, 5]:
            raise ParseError(
                'Invalid attribute definition',
                name=state['file'],
                line=state['line'])

        vendor = state['vendor']
        has_tag = False
        encrypt = 0
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            for (key, val) in options:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Invalid encryption value: %s' % val,
                                file=state['file'],
                                line=state['line'])
                    encrypt = int(val)

            if (not has_tag) and encrypt == 0:
                vendor = tokens[4]
                if vendor not in self.vendors:
                    if vendor == "concat":
                        # Ignore attributes with freeradius datatype concat.
                        return None
                    else:
                        raise ParseError('Unknown vendor ' + vendor,
                                         file=state['file'],
                                         line=state['line'])

        (attribute, code, datatype) = tokens[1:4]
        codes = code.split('.')

        if len(codes) > 0 and codes[0] != '':
            state['parent_code'] = None

        if datatype == 'struct' or datatype == 'tlv':
            state['parent_code'] = codes[0]

        if len(codes) > 0 and codes[0] == '':
            codes[0] = state['parent_code']

        is_sub_attribute = (len(codes) > 1)

        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
        elif len(codes) == 1:
            code = int(codes[0])
        else:
            raise ParseError('Nesting tlvs not supported')

        datatype = datatype.split("[")[0]

        if datatype not in ENCODERS:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])
        if vendor:
            if is_sub_attribute:
                key = (self.vendors.get(vendor), parent_code, code)
            else:
                key = (self.vendors.get(vendor), code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        try:
            self.attrindex[attribute] = key
        except bidict.ValueDuplicationError:
            return

        self.attributes[attribute] = Attribute(attribute,
                                               code,
                                               datatype,
                                               is_sub_attribute,
                                               vendor,
                                               encrypt=encrypt,
                                               has_tag=has_tag)
        if datatype == 'tlv':
            state['tlvs'][code] = self.attributes[attribute]
        if is_sub_attribute:
            state['tlvs'][parent_code].sub_attributes[code] = attribute
            self.attributes[attribute].parent = state['tlvs'][parent_code]

    def _parse_value(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Invalid value statement',
                             file=state['file'],
                             line=state['line'])

        (attr, key, value) = tokens[1:]

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError("Attribute '%s' not found" % attr +
                             " for value statement",
                             file=state['file'],
                             line=state['line'])

        if adef.type in ['integer', 'signed', 'short', 'byte', 'integer64']:
            value = int(value, 0)
        try:
            self.attributes[attr].values[key] = encode(adef.type,
                                                       value)
        except bidict.ValueDuplicationError:
            log.warning("Dictionary '%s'" % state['file'] +
                        " Duplicate Value '%s'" % attr +
                        " for Attribute '%s'" % value)

    def _parse_vendor(self, state, tokens):
        if len(tokens) not in [3, 4]:
            raise ParseError(
                    'Invalid vendor definition',
                    file=state['file'],
                    line=state['line'])

        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'])
            try:
                (t, l) = tuple(int(a) for a in fmt[1].split(','))
                if t not in [1, 2, 4] or l not in [0, 1, 2]:
                    raise ParseError(
                        'Unknown vendor format specification %s' % (fmt[1]),
                        file=state['file'],
                        line=state['line'])
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'])

        (vendorname, vendor) = tokens[1:3]
        self.vendors[vendorname] = int(vendor, 0)

    def _parse_begin_vendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                    'Invalid begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        vendor = tokens[1]

        if vendor not in self.vendors:
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = vendor

    def _parse_end_vendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Invalid end-vendor statement',
                file=state['file'],
                line=state['line'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Non-open vendor end statement' + vendor,
                    file=state['file'],
                    line=state['line'])
        state['vendor'] = ''

    def _parse(self, dictfile):
        state = {}
        state['vendor'] = ''
        state['parent_code'] = ''
        state['tlvs'] = {}
        self.defer_parse = []
        for line in dictfile:
            state['file'] = dictfile.file()
            state['line'] = dictfile.line()
            line = line.split('#', 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == 'ATTRIBUTE':
                self._parse_attribute(state, tokens)
            elif key == 'VALUE':
                self._parse_value(state, tokens, True)
            elif key == 'VENDOR':
                self._parse_vendor(state, tokens)
            elif key == 'BEGIN-VENDOR':
                self._parse_begin_vendor(state, tokens)
            elif key == 'END-VENDOR':
                self._parse_end_vendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == 'VALUE':
                self._parse_value(state, tokens, False)
        self.defer_parse = []

    def parse_file(self, dictionary):
        dictfile = FileLexer(dictionary)
        self._parse(dictfile)
        return self

    def parse_package(self, dictionary):
        dictfile = PackageLexer(dictionary)
        self._parse(dictfile)
        return self
