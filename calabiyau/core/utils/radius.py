# -*- coding: utf-8 -*-
# Copyright (c) 2019 Christiaan Frans Rademan <christiaan.rademan@gmail.com>
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
import hmac
import select
import struct
import socket
import binascii
import hashlib
from ipaddress import ip_address
from ipaddress import ip_network

from luxon import GetLogger
from luxon.utils.unique import random_generator
from luxon.utils.network import get_addr_info

from calabiyau.exceptions import PacketError, ServerPacketError

log = GetLogger(__name__)


def bind_udp_radius(addr, port):
    """Bind UDP Socket for Radius.
    """
    socket_descriptors = []
    family_addr = get_addr_info(addr)
    for (family, address) in family_addr:
        sd = socket.socket(family, socket.SOCK_DGRAM)
        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sd.bind((address, port))
        socket_descriptors.append(sd)

    return socket_descriptors


def create_identifier():
    """Generate a unique identifier/packet id.

    The Identifier field is one octet, and aids in matching requests and
    replies.  The RADIUS server can detect a duplicate request if it has the
    same client source IP address and source UDP port and Identifier within a
    short span of time.

    Reference IETF RFC 2865 Section 3.

    Returns random 8 bit integer
    """
    return random_generator.randrange(1, 255)


def create_authenticator():
    """Generate a unique autenticator.

    The Authenticator field is sixteen (16) octets.  The most significant octet
    is transmitted first.  This value is used to authenticate the reply from
    the RADIUS server, and is used in the password hiding algorithm.

    This function returns a suitable random string that can be used for
    generating the final authenticator. There is a difference in the final
    request and response authenticator which is handled by the Packet class.

    Reference IETF RFC 2865 Section 3.
    """
    return struct.pack('!QQ',
                       random_generator.randrange(0, pow(2, 64)),
                       random_generator.randrange(0, pow(2, 64)))


def encode_string(string):
    """Encode String Data Type.

    The "string" data type encodes binary data as a sequence of undistinguished
    octets. Where the range of lengths for a particular attribute is limited to
    a subset of possible lengths, specifications MUST define the valid range.
    Attributes with lengths outside of the allowed values SHOULD be treated as
    invalid attributes.

    Attributes of type "string" that are allocated in the standard space
    (Section 1.2 of [RFC6929]) are limited to no more than 253 octets of data.

    Attributes of type "string" that are allocated in the extended space can be
    longer.  In both cases, these limits are reduced when the data is
    encapsulated inside of another attribute.

    Reference IETF RFC 8044 Section 3.5.
    """

    if len(string) > 253:
        raise ValueError('Encode only strings of <= 253 characters')

    try:
        return string.encode('utf-8')
    except AttributeError:
        return string


def decode_string(string):
    """Decode String Data Type.

    The "string" data type encodes binary data as a sequence of undistinguished
    octets. Where the range of lengths for a particular attribute is limited to
    a subset of possible lengths, specifications MUST define the valid range.
    Attributes with lengths outside of the allowed values SHOULD be treated as
    invalid attributes.

    Attributes of type "string" that are allocated in the standard space
    (Section 1.2 of [RFC6929]) are limited to no more than 253 octets of data.

    Attributes of type "string" that are allocated in the extended space can be
    longer.  In both cases, these limits are reduced when the data is
    encapsulated inside of another attribute.

    Reference IETF RFC 8044 Section 3.5.
    """
    try:
        return string.decode('utf-8')
    except Exception:
        return string


def encode_octets(string):
    if len(string) > 253:
        raise ValueError('Encode only strings of <= 253 characters')

    if isinstance(string, bytes):
        return string
    else:
        string = str(string)
        if string.startswith('0x'):
            hexstring = string.split('0x')[1]
            return binascii.unhexlify(hexstring)
        else:
            return string


def decode_octets(octects):
    return octects


def encode_address(address):
    return ip_address(address).packed


def decode_address(address):
    return '.'.join(map(str, struct.unpack('BBBB',
                                           address)))


def encode_ipv6_prefix(prefix):
    ip = ip_network(prefix, False)
    return struct.pack('2B', *[0, ip.prefixlen]) + ip.network_address.packed


def decode_ipv6_prefix(prefix):
    prefix = prefix + b'\x00' * (18-len(prefix))
    _, length, ip = ':'.join(map('{0:x}'.format,
                             struct.unpack('!BB'+'H'*8,
                                           prefix))).split(":", 2)
    return str(ip_network("%s/%s" % (ip, int(length, 16)), False))


def encode_ipv6_address(addr):
    return ip_address(addr).packed


def decode_ipv6_address(address):
    address = address + b'\x00' * (16-len(address))
    prefix = ':'.join(map('{0:x}'.format, struct.unpack('!'+'H'*8, address)))
    return str(ip_address(prefix))


def encode_byte(integer):
    try:
        return struct.pack('!B', int(integer))
    except ValueError:
        raise TypeError('Encode non-integer as integer')


def decode_byte(integer):
    return (struct.unpack('!B', integer))[0]


def encode_integer(integer):
    try:
        return struct.pack('!I', int(integer))
    except ValueError:
        raise TypeError('Encode non-integer as integer')


def decode_integer(integer):
    return (struct.unpack('!I', integer))[0]


def encode_signed(integer):
    try:
        return struct.pack('!i', int(integer))
    except ValueError:
        raise TypeError('Encode non-integer as integer')


def decode_signed(integer):
    return (struct.unpack('!i', integer))[0]


def encode_short(integer):
    try:
        return struct.pack('!H', int(integer))
    except ValueError:
        raise TypeError('Encode non-integer as integer')


def decode_short(integer):
    return (struct.unpack('!H', integer))[0]


def encode_integer64(integer, pack_format='!Q'):
    try:
        return struct.pack('!Q', int(integer))
    except ValueError:
        raise TypeError('Encode non-integer as integer64')


def decode_integer64(integer):
    return (struct.unpack('!Q', integer))[0]


def encode_date(integer):
    if not isinstance(integer, int):
        raise TypeError('Encode non-integer as date')
    return struct.pack('!I', integer)


def decode_date(integer):
    return (struct.unpack('!I', integer))[0]


ENCODERS = {'string': encode_string,
            'octets': encode_octets,
            'integer': encode_integer,
            'integer64': encode_integer64,
            'ipaddr': encode_address,
            'ipv6prefix': encode_ipv6_prefix,
            'ipv6addr': encode_ipv6_address,
            'signed': encode_signed,
            'short': encode_short,
            'byte': encode_byte,
            'date': encode_date,
            'ifid': encode_octets,
            'tlv': encode_octets,
            'vsa': encode_octets}


DECODERS = {'string': decode_string,
            'octets': decode_octets,
            'integer': decode_integer,
            'integer64': decode_integer64,
            'ipaddr': decode_address,
            'ipv6prefix': decode_ipv6_prefix,
            'ipv6addr': decode_ipv6_address,
            'signed': decode_signed,
            'short': decode_short,
            'byte': decode_byte,
            'date': decode_date,
            'ifid': decode_octets,
            'tlv': decode_octets,
            'vsa': decode_octets}


def encode(datatype, value):
    try:
        return ENCODERS[datatype](value)
    except KeyError:
        raise ValueError('Unknown attribute type %s' % datatype)


def decode(datatype, value):
    try:
        return DECODERS[datatype](value)
    except KeyError:
        raise ValueError('Unknown attribute type %s' % datatype)


def salt_encrypt(pkt, value):
    if isinstance(value, str):
        value = value.encode('utf-8')

    if pkt.authenticator is None:
        authenticator = 16 * b'\x00'

    salt = struct.pack('!H', random_generator.randrange(0, 65535))
    salt = chr(ord(salt[0]) | 1 << 7)+salt[1]

    length = struct.pack("B", len(value))
    buf = length + value
    if len(buf) % 16 != 0:
        buf += b'\x00' * (16 - (len(buf) % 16))

    result = bytes(salt)

    last = authenticator + salt
    while buf:
        hash = hashlib.md5(pkt.secret + last).digest()
        for i in range(16):
            result += bytes((hash[i] ^ buf[i],))

        last = result[-16:]
        buf = buf[16:]

    return result


def password_decrypt(pkt, password):
    buf = password
    pw = b''

    last = pkt.authenticator
    while buf:
        hash = hashlib.md5(pkt.secret + last).digest()
        for i in range(16):
            pw += bytes((hash[i] ^ buf[i],))
        (last, buf) = (buf[:16], buf[16:])

    while pw.endswith(b'\x00'):
        pw = pw[:-1]

    return pw.decode('utf-8')


def password_encrypt(pkt, password):
    if isinstance(password, str):
        password = password.encode('utf-8')

    buf = password
    if len(password) % 16 != 0:
        buf += b'\x00' * (16 - (len(password) % 16))

    hash = hashlib.md5(pkt.secret + pkt.authenticator).digest()
    result = b''

    last = pkt.authenticator
    while buf:
        hash = hashlib.md5(pkt.secret + last).digest()
        for i in range(16):
            result += bytes((hash[i] ^ buf[i],))

        last = result[-16:]
        buf = buf[16:]

    return result


def validate_chap_password(pkt, userpwd):
    if isinstance(userpwd, str):
        userpwd = userpwd.strip().encode('utf-8')

    chap_password = decode_octets(pkt.get(3)[0])
    if len(chap_password) != 17:
        return False

    chapid = chap_password[:1]
    password = chap_password[1:]

    challenge = pkt.authenticator
    if 'CHAP-Challenge' in pkt:
        challenge = pkt['CHAP-Challenge'][0]
    return password == hashlib.md5(chapid + userpwd + challenge).digest()


def decode_value(pkt, attr, value):
    try:
        return attr.values.inverse[value]
    except KeyError:
        if attr.encrypt == 1:
            return password_decrypt(pkt, value)
        else:
            return decode(attr.type, value)


def encode_value(pkt, attr, value):
    result = ''
    try:
        result = attr.values[value]
    except KeyError:
        if attr.encrypt == 1:
            return password_encrypt(pkt, value)
        elif attr.encrypt == 2:
            return salt_encrypt(pkt, result)
        else:
            return encode(attr.type, value)

    return result


def encode_key(pkt, key):
    if not isinstance(key, str):
        return key

    attr = pkt._raddict.attributes[key]
    if attr.vendor and not attr.is_sub_attribute:
        return (pkt._raddict.vendors.get(attr.vendor), attr.code)
    else:
        return attr.code


def decode_key(pkt, key):
    if key in pkt._raddict.attrindex.inverse:
        return pkt._raddict.attrindex.inverse.get(key)
    return key


def encode_key_values(pkt, key, values):
    if not isinstance(key, str):
        return (key, values)

    key, _, tag = key.partition(":")
    attr = pkt._raddict.attributes[key]
    key = encode_key(pkt, key)
    if tag:
        tag = struct.pack('B', int(tag))
        if attr.type == "integer":
            return (key,
                    [tag + encode_value(pkt, attr, v)[1:]
                     for v in values])
        else:
            return (key,
                    [tag + encode_value(pkt, attr, v)
                     for v in values])
    else:
        return (key, [encode_value(pkt, attr, v) for v in values])


def encode_attribute(key, value):
    if isinstance(key, tuple):
        value = struct.pack('!L', key[0]) + \
            encode_attribute(key[1], value)
        key = 26

    return struct.pack('!BB', key, (len(value) + 2)) + value


def encode_tlv(pkt, tlv_key, tlv_value):
    tlv_attr = pkt._raddict.attributes[decode_key(pkt, tlv_key)]
    curr_avp = b''
    avps = []
    max_sub_attribute_len = max(map(lambda item: len(item[1]),
                                    tlv_value.items()))
    for i in range(max_sub_attribute_len):
        sub_attr_encoding = b''
        for (code, datalst) in tlv_value.items():
            if i < len(datalst):
                sub_attr_encoding += encode_attribute(code,
                                                      datalst[i])
        if (len(sub_attr_encoding) + len(curr_avp)) < 245:
            curr_avp += sub_attr_encoding
        else:
            avps.append(curr_avp)
            curr_avp = sub_attr_encoding
    avps.append(curr_avp)
    tlv_avps = []
    for avp in avps:
        value = struct.pack('!BB', tlv_attr.code, (len(avp) + 2)) + avp
        tlv_avps.append(value)
    if tlv_attr.vendor:
        vendor_avps = b''
        for avp in tlv_avps:
            vendor_avps += struct.pack(
                '!BBL', 26, (len(avp) + 6),
                pkt._raddict.vendors.get(tlv_attr.vendor)
            ) + avp
        return vendor_avps
    else:
        return b''.join(tlv_avps)


def encode_attributes(pkt):
    result = b''
    for (code, datalst) in pkt.items():
        if isinstance(code, int) and code > 255:
            continue
        try:
            if pkt._raddict.attributes[decode_key(
                    pkt, code)].type == 'tlv':
                result += encode_tlv(pkt, code, datalst)
            else:
                for data in datalst:
                    result += encode_attribute(code, data)
                    if code == 80:
                        pkt._ma = len(result) - 16
        except KeyError:
            # Unknown Attribute
            pass
    return result


def decode_tlv_attribute(pkt, code, data):
    sub_attributes = pkt.setdefault(code, {})
    loc = 0

    while loc < len(data):
        type, length = struct.unpack('!BB', data[loc:loc+2])[0:2]
        sub_attributes.setdefault(type, []).append(data[loc+2:loc+length])
        loc += length


def decode_vendor_attribute(pkt, data):
    if len(data) < 6:
        return [(26, data)]

    (vendor, type, length) = struct.unpack('!LBB', data[:6])[0:3]

    try:
        if pkt._raddict.attributes[decode_key(pkt,
                                              (vendor,
                                               type))].type == 'tlv':
            decode_tlv_attribute((vendor, type),
                                 data[6:length + 4])
            tlvs = []
        else:
            tlvs = [((vendor, type), data[6:length + 4])]
    except Exception:
        return [(26, data)]

    sumlength = 4 + length
    while len(data) > sumlength:
        try:
            type, length = struct.unpack(
                '!BB', data[sumlength:sumlength+2])[0:2]
        except Exception:
            return [(26, data)]
        tlvs.append(((vendor, type), data[sumlength+2:sumlength+length]))
        sumlength += length
    return tlvs


def send_udp_packet(raw_packet, socket, destination, port):
    socket.sendto(raw_packet, (destination, port))


def client_udp_socket(server, poll=None):
    try:
        family = socket.getaddrinfo(server, 'www')[0][0]
    except Exception:
        family = socket.AF_INET

    sock = socket.socket(family,
                         socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET,
                    socket.SO_REUSEADDR, 1)
    if poll:
        poll.register(sock, select.POLLIN)

    return sock


def close_udp_socket(socket, poll=None):
    if poll:
        poll.unregister(socket)

    socket.close()


def duplicate(raw_packet, destination, port):
    sock = client_udp_socket(destination)
    try:
        send_udp_packet(raw_packet, sock, destination, port)
    finally:
        close_udp_socket(sock)


# TBC - Import issues to implement this now.
# def decode_packet(raw_packet):
#    return Packet(raw_packet=raw_packet)


def encode_packet(pkt):
    attr = bytearray(encode_attributes(pkt))
    if pkt._parent and 'Message-Authenticator' in pkt._parent:
        ma_pos = len(attr)
        attr += encode_attribute(80, 16 * b'\x00')
    elif not pkt._parent and pkt.code in [1, 4, 12, 40, 43]:
        ma_pos = len(attr)
        attr += encode_attribute(80, 16 * b'\x00')

    header = struct.pack('!BBH', pkt.code, pkt.id, (20 + len(attr)))

    if pkt.code not in [1, 4, 12, 40, 43]:
        authenticator = hashlib.md5(header[0:4] + pkt.authenticator +
                                    attr + pkt.secret).digest()
    elif pkt.code in [1]:
        authenticator = pkt.authenticator
    elif pkt.code in [4, 12, 40, 43]:
        authenticator = 16 * b'\x00'

    if pkt._parent and 'Message-Authenticator' in pkt._parent:
        digest = hmac.new(pkt.secret,
                          header + pkt._parent.authenticator + attr).digest()
        attr[ma_pos:] = encode_attribute(80, digest)

        authenticator = hashlib.md5(header[0:4] + pkt.authenticator +
                                    attr + pkt.secret).digest()
    elif not pkt._parent and pkt.code in [1, 4, 12, 40, 43]:
        digest = hmac.new(pkt.secret,
                          header + authenticator + attr).digest()
        attr[ma_pos:] = encode_attribute(80, digest)

        if pkt.code in [4, 12, 40, 43]:
            authenticator = hashlib.md5(header[0:4] + authenticator +
                                        attr + pkt.secret).digest()

    return header + authenticator + attr


def decode_header(raw_packet):
    try:
        return struct.unpack('!BBH16s', raw_packet[0:20])
    except struct.error:
        raise PacketError('Packet header is corrupt')


def encode_header(code, pkt_id, length=20, authenticator=None):
    if authenticator is None:
        authenticator = create_authenticator()

    return bytearray(struct.pack('!BBH16s',
                                 code,
                                 pkt_id,
                                 length,
                                 authenticator))


def add_secret(pkt, hosts):
    if pkt.source[0] in hosts:
        pkt.secret = hosts[pkt.source[0]].secret
    else:
        raise ServerPacketError("Received packet from" +
                                " unknown host '%s:%s'" % pkt.source)
