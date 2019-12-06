# -*- coding: utf-8 -*-
# Copyright (c) 2019-2020 Christiaan Frans Rademan <chris@fwiw.co.za>. <christiaan.rademan@gmail.com>
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
import hmac
import hashlib

from luxon import GetLogger

from calabiyau import constants as const
from calabiyau.core.utils.radius import (create_identifier,
                                         encode_header,
                                         decode_header,
                                         decode_key,
                                         encode_key,
                                         decode_value,
                                         encode_key_values,
                                         encode_packet,
                                         decode_vendor_attribute,
                                         decode_tlv_attribute)
from calabiyau.helpers.radius import dictionary
from calabiyau.exceptions import PacketError

log = GetLogger(__name__)

slots = ('_cached_raw_packet',
         '_raw_packet',
         '_raddict',
         '_ma',
         '_parent',
         'secret',
         'source',
         'fd')

raddict = dictionary()


class Packet(dict):
    __slots__ = slots

    def __init__(self, code=0, pkt_id=None, secret=b'',
                 authenticator=None, parent=None, attributes=None,
                 raw_packet=None):
        super().__init__()

        self._cached_raw_packet = None

        if pkt_id is None:
            pkt_id = create_identifier()

        self.secret = secret
        self._raddict = raddict

        # Message-Authenticator Value Position
        self._ma = None
        self.source = None
        self.fd = None
        self._parent = parent

        self._raw_packet = encode_header(code, pkt_id,
                                         authenticator=authenticator)

        if raw_packet:
            self.raw_packet = raw_packet
        elif isinstance(attributes, dict):
            for (key, value) in attributes.items():
                key = key.replace('_', '-')
                self.add_attribute(key, value)

    def __len__(self):
        return len(self._raw_packet)

    @property
    def code(self):
        return self._raw_packet[0]

    @code.setter
    def code(self, code):
        self._cached_raw_packet = None
        self._raw_packet[0] = code

    @property
    def id(self):
        return self._raw_packet[1]

    @id.setter
    def id(self, pkt_id):
        self._cached_raw_packet = None
        self._raw_packet[1] = pkt_id

    @property
    def authenticator(self):
        return struct.unpack('!16s', self._raw_packet[4:20])[0]

    @authenticator.setter
    def authenticator(self, authenticator):
        self._cached_raw_packet = None
        self._raw_packet[4:20] = authenticator

    @property
    def raw_packet(self):
        if not self._cached_raw_packet:
            self._cached_raw_packet = encode_packet(self)

        return self._cached_raw_packet

    @raw_packet.setter
    def raw_packet(self, packet):
        self._cached_raw_packet = None
        if packet:
            (self.code, self.id, length, self.authenticator) = \
                    decode_header(packet)
            if len(packet) != length:
                raise PacketError('Packet has invalid length')
            if length > 8192:
                raise PacketError('Packet length is too long (%d)' % length)

            self._raw_packet = packet
            self._ma = None
            self.clear()

            packet = packet[20:]
            pos = 20
            while packet:
                try:
                    (key, attrlen) = struct.unpack('!BB', packet[0:2])
                except struct.error:
                    raise PacketError('Attribute header is corrupt')

                if attrlen < 2:
                    raise PacketError(
                            'Attribute length is too small (%d)' % attrlen)

                value = packet[2:attrlen]
                try:
                    attr = self._raddict.attributes[decode_key(self, key)]
                except KeyError:
                    self.setdefault(key, []).append(bytes(value))
                    packet = packet[attrlen:]
                    pos += attrlen
                    continue

                if key == 80:
                    self._ma = pos + 2
                if key == 26:
                    for (key,
                         value) in decode_vendor_attribute(self, value):
                        self.setdefault(key, []).append(bytes(value))
                elif attr.type == 'tlv':
                    decode_tlv_attribute(self, key, bytes(value))
                else:
                    self.setdefault(key, []).append(bytes(value))

                packet = packet[attrlen:]
                pos += attrlen

    def create_reply(self, code=0, attributes={}, **kwargs):
        return Packet(code=code, pkt_id=self.id,
                      secret=self.secret, authenticator=self.authenticator,
                      parent=self, attributes=attributes, **kwargs)

    def verify_reply(self, raw_packet=None):
        if self._parent and self._parent.id != self.id:
            return False

        response_auth = hashlib.md5(raw_packet[0:4] +
                                    bytes(self._parent.raw_packet[4:20]) +
                                    raw_packet[20:] + self.secret).digest()

        if response_auth != raw_packet[4:20]:
            return False

        return True

    def add_attribute(self, key, value):
        dict_key, _, tag = key.partition(":")

        try:
            attr = self._raddict.attributes[dict_key]
        except KeyError:
            raise KeyError("Attribute not supported '%s'" % dict_key)

        if isinstance(value, list):
            (key, value) = encode_key_values(self, key, value)
        else:
            (key, value) = encode_key_values(self, key, [value])

        if attr.is_sub_attribute:
            tlv = self.setdefault(encode_key(self, attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)
        self._cached_raw_packet = None

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return [default]

    def __getitem__(self, key):
        if not isinstance(key, str):
            return dict.__getitem__(self, key)

        values = super().__getitem__(encode_key(self, key))
        attr = self._raddict.attributes[key]
        if attr.type == 'tlv':
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self._raddict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name,
                                   []).append(decode_value(self,
                                                           sub_attr,
                                                           v))
            return res
        else:
            res = []
            for v in values:
                res.append(decode_value(self, attr, v))
            return res

    def __contains__(self, key):
        try:
            return super().__contains__(encode_key(self, key))
        except KeyError:
            return False

    def __delitem__(self, key):
        self._cached_raw_packet = None
        super().__delitem__(self, encode_key(self, key))

    def __setitem__(self, key, item):
        self._cached_raw_packet = None
        if isinstance(key, str):
            (key, item) = encode_key_values(self, key, [item])
            super().__setitem__(key, item)
        else:
            assert isinstance(item, list)
            super().__setitem__(key, item)

    def keys(self):
        return [decode_key(self, key) for key in super().keys()]

    def verify_request(self):
        if 'Message-Authenticator' in self.keys():
            ma_packet = bytearray(self._raw_packet)
            for i, b in enumerate(range(self._ma, self._ma+16)):
                ma_packet[b] = 0
            digest = hmac.new(self.secret, ma_packet).digest()
            return digest == self['Message-Authenticator'][0]
        else:
            return True


class AuthPacket(Packet):
    __slots__ = slots

    def __init__(self, code=const.RAD_ACCESSREQUEST, pkt_id=None,
                 secret=b'', authenticator=None, attributes=None,
                 raw_packet=None):
        super().__init__(code=code,
                         pkt_id=pkt_id,
                         secret=secret,
                         authenticator=authenticator,
                         attributes=attributes,
                         raw_packet=raw_packet)


class AcctPacket(Packet):
    __slots__ = slots

    def __init__(self, code=const.RAD_ACCOUNTINGREQUEST, pkt_id=None,
                 secret=b'', authenticator=None, **attributes):
        super().__init__(code, pkt_id, secret, authenticator, **attributes)

    def create_reply(self, code=const.RAD_ACCOUNTINGRESPONSE, attributes=None,
                     **kwargs):
        return AcctPacket(code=code, pkt_id=self.id,
                          secret=self.secret, authenticator=self.authenticator,
                          parent=self, attributes=attributes, **kwargs)

    def verify_request(self):
        super().verify_request()
        hash = hashlib.md5(self._raw_packet[0:4] + 16 * b'\x00' +
                           self._raw_packet[20:] + self.secret).digest()

        return hash == self.authenticator


class CoAPacket(Packet):
    __slots__ = slots

    def __init__(self, code=const.RAD_COAREQUEST, pkt_id=None, secret=b'',
                 authenticator=None, **attributes):
        super().__init__(code, pkt_id, secret, authenticator, **attributes)

    def create_reply(self, code=const.RAD_COAACK, attributes=None, **kwargs):
        return CoAPacket(code=code, pkt_id=self.id,
                         secret=self.secret, authenticator=self.authenticator,
                         parent=self, attributes=attributes, **kwargs)

    def verify_request(self):
        super().verify_request()
        hash = hashlib.md5(self._raw_packet[0:4] + 16 * b'\x00' +
                           self._raw_packet[20:] + self.secret).digest()

        return hash == self.authenticator
