# -*- coding: utf-8 -*-
# Copyright (c) 2018-2019 Christiaan Frans Rademan.
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
from datetime import datetime
from hashlib import md5
from time import sleep

from luxon import g
from luxon import register
from luxon import GetLogger
from luxon import MPLogger
from luxon import db, dbw
from luxon import MBClient
from luxon.utils.daemon import GracefulKiller
from luxon.utils.encoding import if_unicode_to_bytes
from luxon.utils.timezone import utc

from calabiyau.core.helpers.radius import (get_user,
                                           get_attributes,
                                           has_session,
                                           get_ip,
                                           update_ip,
                                           get_pool_name,
                                           encode_packet)
from calabiyau.core.handlers.radius.server import Server
from calabiyau.constants import RAD_ACCESSACCEPT
from calabiyau.core.utils.radius import (validate_chap_password,
                                         duplicate)

log = GetLogger(__name__)


def usage(crsr, user):
    # Return Values
    # 0 All good.
    # 1 Deactivate Subscriber

    user_id = user['id']

    utc_datetime = datetime.utcnow()
    if user['package_span'] and user['package_span'] > 0:
        if (user['package_expire'] and
                utc(utc_datetime) > utc(user['package_expire'])):
            return 1

    if user:
        # IF DATA PLAN NOT UNCAPPED
        if user['plan'] == 'data':
            volume_used = user['volume_used']
            volume_used_bytes = user['volume_used_bytes']
            ######################
            # CHECK PACKAGE DATA #
            ######################
            package_volume_bytes = user['volume_gb'] * 1024 * 1024 * 1024
            if utc(user['volume_expire']) < utc(utc_datetime):
                if user['volume_repeat']:
                    return 0
                else:
                    log.info('Package data expired (%s)'
                             % user['username'])

            if (not volume_used and
                    volume_used_bytes > package_volume_bytes):
                log.info('Package data depleted (%s)'
                         % user['username'])
            elif (not volume_used and
                    volume_used_bytes <= package_volume_bytes):
                return 0

            ####################
            # CHECK TOPUP DATA #
            ####################
            crsr.execute('SELECT * FROM calabiyau_topup' +
                         ' WHERE user_id = %s' +
                         ' ORDER BY creation_time asc' +
                         ' FOR UPDATE',
                         (user_id,))
            topups = crsr.fetchall()
            for topup in topups:
                if topup['volume_gb']:
                    topup_volume_bytes = (topup['volume_gb'] * 1024 *
                                          1024 * 1024)
                else:
                    topup_volume_bytes = 0

                if utc(topup['volume_expire']) < utc(utc_datetime):
                    if topup['volume_repeat']:
                        log.auth('Topup renew (%s, %s Gb, %s)' %
                                 (user['username'],
                                  topup['volume_gb'],
                                  topup['creation_time'],))
                        db.commit()
                        return 0
                    else:
                        log.auth('Topup expired (%s, %s Gb, %s)' %
                                 (user['username'],
                                  topup['volume_gb'],
                                  topup['creation_time'],))
                else:
                    if volume_used_bytes < topup_volume_bytes:
                        return 0
                    else:
                        log.auth('Topup depleted (%s, %s Gb, %s)' %
                                 (user['username'],
                                  topup['volume_gb'],
                                  topup['creation_time'],))
            return 1
        else:
            return 0


class RadiusServer(Server):
    __slots__ = ()

    def auth(self, pkt, debug):
        with db() as dbro:
            with dbro.cursor() as crsr:
                client = pkt.get('NAS-IP-Address')[0]
                user = get_user(crsr,
                                client,
                                pkt.source[0],
                                pkt.get('User-Name')[0])
                if user:
                    if not user['enabled']:
                        log.auth('Subscriber account disabled (%s)'
                                 % user['username'])
                        dbro.commit()
                        return
                else:
                    log.warning('User not found (%s)'
                                % pkt.get('User-Name')[0])
                    dbro.commit()
                    return

                if ('User-Password' in pkt):
                    if pkt['User-Password'][0] != user['password']:
                        # Check for Legacy MD5 hashed passwords.
                        hashed = md5(
                            pkt['User-Password'][0].encode(
                                'utf-8')).hexdigest()
                        if str(hashed) != user['password']:
                            dbro.commit()
                            log.info('Password mismatch (%s)'
                                        % user['username'])
                            return
                elif ('CHAP-Password' in pkt and
                        not validate_chap_password(pkt, user['password'])):
                    dbro.commit()
                    log.info('Password mismatch (%s)'
                             % user['username'])
                    return
                elif ('User-Password' not in pkt and
                        'CHAP-Password' not in pkt):
                    dbro.commit()
                    log.info('No password supplied (%s)'
                             % user['username'])
                    return

                ctx = usage(crsr, user)
                attributes = get_attributes(crsr, user, ctx)

                if (user['static_ip4'] or
                        not user['simultaneous']):
                    if has_session(crsr, user):
                        log.warning('Subscriber duplicate session (%s)'
                                    % user['username'])
                        dbro.commit()
                        return
                    elif user['static_ip4']:
                        attributes['Framed-IP-Address'] = user['static_ip4']
                elif user['pool_id']:
                    with dbw() as dbwr:
                        ip = get_ip(dbwr, user)
                    if ip:
                        attributes['Framed-IP-Address'] = ip
                    else:
                        pool_name = get_pool_name(crsr, user)
                        log.critical("IP Pool Empty user '%s' pool '%s'"
                                     % (user['username'],
                                        pool_name,))
                        dbro.commit()
                        return

                dbro.commit()
        return (RAD_ACCESSACCEPT,
                attributes)

    def acct(self, pkt, debug):
        with MBClient('subscriber') as mb:
            mb.send('radius_accounting',
                    {'attributes': encode_packet(pkt),
                     'datetime': str(datetime.utcnow())})
        with db() as dbro:
            with dbro.cursor() as crsr:
                client = pkt.get('NAS-IP-Address')[0]
                user = get_user(crsr,
                                client,
                                pkt.source[0],
                                pkt.get('User-Name')[0])
                if user:
                    status = pkt.get('Acct-Status-Type', [''])[0].lower()
                    if not user['static_ip4'] and user['pool_id']:
                        with dbw() as dbwr:
                            update_ip(dbwr, status, user, pkt)

                duplicate_to = g.app.config.get('radius',
                                                'duplicate',
                                                fallback=None)
                if duplicate_to:
                    with dbro.cursor() as crsr:
                        client = pkt.get('NAS-IP-Address')[0]
                        user = get_user(crsr,
                                        client,
                                        pkt.source[0],
                                        pkt.get('User-Name')[0])
                        if user:
                            pkt['Class'] = user['package'].encode('utf-8')
                            duplicates = duplicate_to.split(',')
                            for duplicate_to in duplicates:
                                duplicate_to = duplicate_to.strip()
                                duplicate(pkt.raw_packet, duplicate_to, 1813)

        return True

    def coa(self, pkt, debug):
        return False

    def pod(self, pkt, debug):
        return False

    def status(self, pkt, debug):
        return True


clients_hash = b''


def update_clients(srv):
    global clients_hash

    MPLogger(__name__)

    # add clients (address, secret, name)
    with db() as conn:
        with conn.cursor() as crsr:
            clients = crsr.execute('SELECT INET6_NTOA(server) as server' +
                                   ', secret FROM' +
                                   ' calabiyau_nas').fetchall()
            string = str(clients).encode('utf-8')
            new_hash = md5(string).digest()
            if new_hash != clients_hash:
                if clients:
                    for client in clients:
                        host = client['server']
                        secret = if_unicode_to_bytes(client['secret'])
                        srv.add_host(host,
                                     secret)
                else:
                    srv.set_hosts({})
                clients_hash = new_hash
            crsr.commit()


@register.resource('service', 'radius')
def start(req, resp):
    try:
        procs = []
        mplog = MPLogger('__main__')
        mplog.receive()

        # create server and read dictionary
        srv = RadiusServer(debug=g.app.debug)

        def end(sig):
            for proc, target in procs:
                proc.terminate()
            srv.stop()
            mplog.close()
            exit()

        # start server
        srv.start()

        sig = GracefulKiller(end)

        while not sig.killed:
            update_clients(srv)
            sleep(10)

        end(None)

    except (KeyboardInterrupt, SystemExit):
        end(None)
