# -*- coding: utf-8 -*-
# Copyright (c) 2019 Christiaan Frans Rademan. <christiaan.rademan@gmail.com>
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
import struct

import bidict


class Attribute(object):
    __slots__ = ('name', 'code', 'type', 'vendor', 'encrypt',
                 'has_tag', 'values', 'sub_attributes', 'parent',
                 'is_sub_attribute')

    def __init__(self, name, code, datatype,
                 is_sub_attribute=False, vendor='',
                 values=None, encrypt=0, has_tag=False):

        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = bidict.bidict()
        self.sub_attributes = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for (key, value) in values.items():
                self.values[key] = value

    @property
    def user_values(self):
        user_values = {}
        for value in self.values:
            user_values[value] = struct.unpack('!I', self.values[value])[0]
        return user_values
