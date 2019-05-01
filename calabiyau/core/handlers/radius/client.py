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
import select
import time

from luxon import GetLogger

from calabiyau import exceptions
from calabiyau.core.radius import packet
from calabiyau.core.radius.basehost import BaseHost
from calabiyau.core.utils.radius import (client_udp_socket,
                                         close_udp_socket,
                                         send_udp_packet)

log = GetLogger(__name__)


class Client(BaseHost):
    __slots__ = ('_server', '_secret', '_socket', '_retries', '_timeout',
                 '_poll', '_auth_port', '_acct_port', '_coa_port', '_debug')

    def __init__(self, server, auth_port=1812, acct_port=1813,
                 coa_port=3799, secret=b'', debug=False):

        super().__init__(auth_port, acct_port, coa_port)

        self._debug = debug
        self._server = server
        self._secret = secret
        self._socket = None
        self._retries = 3
        self._timeout = 5
        self._poll = select.poll()

    def auth(self, **args):
        return super().auth_packet(secret=self._secret, **args)

    def acct(self, **args):
        return super().acct_packet(secret=self._secret, **args)

    def coa(self, **args):
        return super().coa_packet(secret=self._secret, **args)

    def pod(self, **args):
        args = {'code': 40, **args}
        return super().coa_packet(secret=self._secret, **args)

    def _socket_open(self):
        self._socket = client_udp_socket(self._server, self._poll)

    def _close_socket(self):
        if self._socket:
            close_udp_socket(self._socket, self._poll)
            self._socket = None

    def _send_packet(self, pkt, port):
        self._socket_open()
        for attempt in range(self._retries):
            if self._debug:
                debug = ("Sending Packet (Attempt %s)" % (attempt + 1,) +
                         " Code '%s' ID '%s'\n" % (pkt.code, pkt.id,))
                debug += " Destination: %s:%s\n" % (self._server, port,)
                for attr in pkt.keys():
                    try:
                        debug += " %s = %s\n" % (attr, pkt[attr],)
                    except Exception:
                        debug += (" %s = ?\n" % attr)

            if attempt and pkt.code == 4:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = \
                            pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self._timeout
            send_udp_packet(pkt.raw_packet, self._socket, self._server, port)

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.time()
                    continue

                reply = pkt.create_reply(raw_packet=rawreply)

                if reply.verify_reply(rawreply):
                    if self._debug:
                        debug += ("Received Packet" +
                                  " Code '%s' ID '%s'\n" % (reply.code,
                                                            reply.id,))
                        for attr in reply.keys():
                            try:
                                debug += " %s = %s\n" % (attr, reply[attr],)
                            except Exception:
                                debug += (" %s = ?\n" % attr)
                    if self._debug:
                        log.debug(debug)
                    return reply

                now = time.time()

            if self._debug:
                debug += " Timeout for server response."
                log.debug(debug)
        raise exceptions.TimeoutError

    def send_packet(self, pkt):
        if isinstance(pkt, packet.AuthPacket):
            return self._send_packet(pkt, self._auth_port)
        elif isinstance(pkt, packet.AcctPacket):
            return self._send_packet(pkt, self._acct_port)
        elif isinstance(pkt, packet.CoAPacket):
            return self._send_packet(pkt, self._coa_port)
