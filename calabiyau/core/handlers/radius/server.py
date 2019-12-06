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
import binascii
import traceback
from time import time
from hashlib import md5
from multiprocessing import (Queue,
                             current_process,
                             cpu_count)

from luxon import GetLogger
from luxon.exceptions import SQLError
from luxon.utils.multiproc import ProcessManager
from luxon.utils.multithread import ThreadManager

from calabiyau import constants as const
from calabiyau.core.radius.basehost import BaseHost
from calabiyau.core.radius.remotehost import RemoteHost
from calabiyau.exceptions import ServerPacketError, PacketError
from calabiyau.core.utils.radius import bind_udp_radius, add_secret

log = GetLogger(__name__)

# According to RFC 2865 that details the RADIUS protocol, although the Radius
# packet length field is 2 octets long, the maximum packet size is restricted
# to 4096 bytes.
MAXPACKETSIZE = 4096


class Server(BaseHost):
    __slots__ = ('_hosts', '_addresses', '_auth', '_acct', '_coa',
                 '_procs', '_threads', '_auth_port', '_acct_port',
                 '_coa_port', '_debug', '_rpc_proc_queues',
                 '_running', '_subproc', '_pm', '_pmi', '_queue')

    def __init__(self, addresses=['0.0.0.0'], auth_port=1812, acct_port=1813,
                 coa_port=3799, auth_enabled=True, acct_enabled=True,
                 coa_enabled=True, threads=8, procs=cpu_count() * 4,
                 debug=False, process_manager=None, queue_size=65536):

        self._debug = debug

        super().__init__(auth_port, acct_port, coa_port)
        self._hosts = {}

        self._addresses = frozenset(addresses)

        self._auth = []
        self._acct = []
        self._coa = []

        for addr in addresses:
            if auth_enabled:
                self._auth += bind_udp_radius(addr, auth_port)
            if acct_enabled:
                self._acct += bind_udp_radius(addr, acct_port)
            if coa_enabled:
                self._coa += bind_udp_radius(addr, coa_port)

        self._procs = procs
        self._threads = threads
        self._rpc_proc_queues = []
        self._running = False
        self._subproc = False
        if process_manager:
            self._pm = process_manager
            self._pmi = False
        else:
            self._pm = ProcessManager()
            self._pmi = True

        self.instantiate(debug)
        self._queue = Queue(maxsize=queue_size)

    @property
    def queue(self):
        return self._queue

    def instantiate(self, debug):
        pass

    def auth(self, pkt, queue, debug):
        return False

    def acct(self, pkt, queue, debug):
        return False

    def coa(self, pkt, queue, debug):
        return False

    def pod(self, pkt, queue, debug):
        return False

    def status(self, pkt, queue, debug):
        return True

    def create_reply_packet(self, pkt, code, attributes={}):
        reply = pkt.create_reply(code=code, attributes=attributes)
        reply.source = pkt.source
        return reply

    def _handle_auth(self, pkt, queue, debug):
        if pkt.code not in (1, 12,):
            raise ServerPacketError('Received non-authentication packet' +
                                    ' on authentication port')
        if not pkt.verify_request():
            raise ServerPacketError('Received request' +
                                    ' from %s:%s' % pkt.source +
                                    ' with invalid' +
                                    ' Message-Authenticator!' +
                                    ' (Shared secret is incorrect)')
        if 'NAS-IP-Address' not in pkt:
            pkt['NAS-IP-Address'] = pkt.source[0]
        if pkt.code == 1:
            pkt['Client-IP-Address'] = pkt.source[0]
            result = self.auth(pkt, queue, debug)
        elif self.status(pkt, queue, debug):
            return (const.RAD_ACCESSACCEPT, None)
        else:
            return

        try:
            code, attributes = result
            attributes['Class'] = md5(pkt.raw_packet +
                                      str(pkt.source).encode('utf-8')).digest()
        except TypeError:
            return (const.RAD_ACCESSREJECT, None)
        except ValueError:
            # Returned invalid values
            return

        return (code, attributes)

    def _handle_acct(self, pkt, queue, debug):
        if pkt.code not in (4, 12,):
            raise ServerPacketError('Received non-accounting packet' +
                                    ' on accounting port')

        if not pkt.verify_request():
            raise ServerPacketError('Received accounting request' +
                                    ' from %s:%s' % pkt.source +
                                    ' with invalid' +
                                    ' Request-Authenticator!' +
                                    ' (Shared secret is incorrect)')

        if 'NAS-IP-Address' not in pkt:
            pkt['NAS-IP-Address'] = pkt.source[0]
        if 'Class' in pkt:
            session_id = binascii.hexlify(pkt['Class'][0])
        elif 'Acct-Session-Id' in pkt:
            session_id = md5(
                pkt['Acct-Session-Id'][0].encode('utf-8') +
                str(pkt.get('NAS-IP-Address')[0]).encode('utf-8')).hexdigest()
        else:
            session_id = md5(
                pkt.get('User-Name')[0].encode('utf-8'),
                pkt.get('Framed-IP-Address')[0].encode('utf-8')).hexdigest()

        pkt['Client-IP-Address'] = pkt.source[0]
        pkt['Acct-Session-Start-Time'] = int(time())
        pkt['Acct-Unique-Session-Id'] = session_id
        if 'Acct-Input-Gigawords' in pkt:
            pkt['Acct-Input-Octets64'] = (
            (pkt['Acct-Input-Gigawords'][0] << 32) +
            pkt.get('Acct-Input-Octets', 0)[0])
        else:
            pkt['Acct-Input-Octets64'] = pkt.get('Acct-Input-Octets', 0)[0]

        if 'Acct-Output-Gigawords' in pkt:
            pkt['Acct-Output-Octets64'] = ((pkt.get(
               'Acct-Output-Gigawords', 0)[0] << 32)
                + pkt.get('Acct-Output-Octets', 0)[0])
        else:
            pkt['Acct-Output-Octets64'] = pkt.get('Acct-Output-Octets', 0)[0]

        if pkt.code == 4 and self.acct(pkt, queue, debug):
            return (const.RAD_ACCOUNTINGRESPONSE, None)
        elif pkt.code == 12 and self.status(pkt, queue, debug):
            return (const.RAD_ACCOUNTINGRESPONSE, None)
        else:
            return

    def _handle_coa(self, pkt, queue, debug):
        if pkt.code not in (40, 43,):
            raise ServerPacketError('Received non-coa/pod packet' +
                                    ' on coa port')

        if not pkt.verify_request():
            raise ServerPacketError('Received coa/pod request' +
                                    ' from %s:%s' % pkt.source +
                                    ' with invalid' +
                                    ' Request-Authenticator!' +
                                    ' (Shared secret is incorrect)')

        if pkt.code == 43:
            if self.coa(pkt, queue, debug):
                return (const.RAD_COAACK, None)
            else:
                return (const.RAD_COANACK, None)
        elif pkt.code == const.RAD_DISCONNECTREQUEST:
            if self.pod(pkt, queue, debug):
                return (const.RAD_DISCONNECTACK, None)
            else:
                return (const.RAD_DISCONNECTNAK, None)
        else:
            raise ServerPacketError('Received non-coa packet on coa port')

    def _thread(self, fd, pktgen, handle, queue):
        _debug = self._debug

        while True:
            try:
                data, source = fd.recvfrom(MAXPACKETSIZE)
                pkt = pktgen(raw_packet=data)
                pkt.source = source
                pkt.fd = fd
                add_secret(pkt, self._hosts)
                if _debug:
                    debug = ("Received Packet" +
                             " Code '%s' ID '%s'\n" % (pkt.code, pkt.id,))
                    debug += " Source: %s:%s\n" % pkt.source
                    for attr in pkt.keys():
                        try:
                            debug += " %s = %s\n" % (attr, pkt[attr],)
                        except Exception:
                            debug += (" %s = ?\n" % attr)
                try:
                    result = handle(pkt, queue, _debug)
                    try:
                        code, attributes = result
                    except TypeError:
                        if _debug:
                            log.debug(debug)
                        continue

                    self.send_reply_packet(fd,
                                           self.create_reply_packet(
                                               pkt,
                                               code,
                                               attributes))
                    if _debug:
                        if attributes is None:
                            attributes = {}
                        debug += ("Responding Packet" +
                                  " Code '%s' ID '%s'\n" % (code,
                                                            pkt.id,))
                        debug += " Destination: %s:%s\n" % pkt.source
                        for attr in attributes:
                            debug += " %s = %s\n" % (attr, attributes[attr],)
                        log.debug(debug)
                except SQLError as err:
                    log.critical('Database error' +
                                 ' processing REPLY: ' +
                                 str(err))
            except ServerPacketError as err:
                log.error('Dropping packet: ' + str(err))
            except PacketError as err:
                log.error('Received broken packet: ' + str(err))
            except Exception as err:
                log.critical('Unexpected error in' +
                             ' processing thread: ' + str(err) +
                             '\n' + str(traceback.format_exc()))

    def proc_rpc(self, method, *args, **kwargs):
        for queue in self._rpc_proc_queues:
            queue.put((method, args, kwargs))

    def _rpc(self, queue):
        while True:
            try:
                method, args, kwargs = queue.get()
                method = getattr(self, method)
                method(*args, **kwargs)
            except Exception as err:
                log.critical('Unexpected error in' +
                             ' processing rpc: ' + str(err) +
                             '\n' + str(traceback.format_exc()))

    def _process(self, fd, pktgen, handle, rpc_proc_queue, queue):
        self._subproc = True
        proc_name = current_process().name
        tm = ThreadManager()

        tm.new(self._rpc,
               '%s-RPC' % proc_name,
               restart=True,
               args=(rpc_proc_queue,))

        for thread in range(self._threads):
            tm.new(self._thread,
                   '%s-%s' % (proc_name, thread+1,),
                   kwargs={'fd': fd,
                           'pktgen': pktgen,
                           'handle': handle,
                           'queue': queue})

        tm.start()

    def add_host(self, host, secret, name=None, auth_port=1812,
                 acct_port=1813, coa_port=3799):
        if not name:
            name = host

        self._hosts[host] = RemoteHost(host,
                                       secret,
                                       name,
                                       auth_port,
                                       acct_port,
                                       coa_port)
        if not self._subproc:
            if self._running:
                self.proc_rpc('set_hosts', self._hosts)

    def remove_host(self, host):
        try:
            del self._host[host]
        except KeyError:
            pass

        if not self._subproc:
            if self._running:
                self.proc_rpc('set_hosts', self._hosts)

    @property
    def hosts(self):
        return tuple([host for host in self._hosts])

    @hosts.setter
    def hosts(self, hosts):
        self._hosts = {}
        for host in hosts:
            try:
                host = host['host']
                secret = host['secret']
            except KeyError:
                log.error('Require host and secret for hosts in server')
                return

            name = host.get('name', host)
            auth_port = host.get('auth_port', 1812)
            acct_port = host.get('acct_port', 1813)
            coa_port = host.get('acct_port', 3799)

            self._hosts[host] = RemoteHost(host,
                                           secret,
                                           name,
                                           auth_port,
                                           acct_port,
                                           coa_port)

        if not self._subproc:
            if self._running:
                self.proc_rpc('set_hosts', self._hosts)

    def set_hosts(self, hosts):
        self._hosts = hosts
        if not self._subproc:
            if self._running:
                self.proc_rpc('set_hosts', self._hosts)

    def start(self):
        self._running = True
        for fd in (self._auth + self._acct + self._coa):
            for proc in range(self._procs):
                rpc_proc_queue = Queue()
                self._rpc_proc_queues.append(rpc_proc_queue)
                socket_info = fd.getsockname()
                if fd in self._auth:
                    name = 'AUTH(%s:%s)%s' % (socket_info[0],
                                              socket_info[1],
                                              proc+1)
                    pktgen = self.auth_packet
                    handle = self._handle_auth
                elif fd in self._acct:
                    name = 'ACCT(%s:%s)%s' % (socket_info[0],
                                              socket_info[1],
                                              proc+1,)
                    pktgen = self.acct_packet
                    handle = self._handle_acct
                elif fd in self._coa:
                    name = 'COA(%s:%s)%s' % (socket_info[0],
                                             socket_info[1],
                                             proc+1,)
                    pktgen = self.coa_packet
                    handle = self._handle_coa

                self._pm.new(self._process,
                             name,
                             restart=True,
                             kwargs={'fd': fd,
                                     'pktgen': pktgen,
                                     'handle': handle,
                                     'rpc_proc_queue': rpc_proc_queue,
                                     'queue': self._queue})
        if self._pmi:
            self._pm.start()
