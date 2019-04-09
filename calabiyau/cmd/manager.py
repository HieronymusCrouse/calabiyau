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
import time
from ipaddress import ip_network
from multiprocessing import Process, cpu_count

from luxon import register
from luxon import MBServer
from luxon import MPLogger
from luxon import GetLogger
from luxon import db, dbw
from luxon.utils.mysql import retry
from luxon.utils.daemon import GracefulKiller
from luxon.exceptions import SQLIntegrityError

from calabiyau.msgbus.radius.acct import acct as radius_acct
from calabiyau.helpers.nas import get_nas_secret
from calabiyau.helpers.users import get_username
from calabiyau.utils.radius import pod


log = GetLogger(__name__)


@retry()
def purge_sessions():
    log = MPLogger(__name__)
    with dbw() as conn:
        with conn.cursor() as crsr:
            while True:
                log.info('Purging old stop sessions')
                crsr.execute("DELETE FROM calabiyau_session WHERE" +
                             " processed < (NOW() - INTERVAL 8 HOUR)" +
                             " AND accttype = 'stop'")
                crsr.commit()
                time.sleep(60)


@retry()
def append_pool(msg):
    log = MPLogger(__name__)
    pool_id = msg['pool_id'].replace(' ', '')
    prefix = msg['prefix']
    with dbw() as conn:
        with conn.cursor() as crsr:
            bulk = []
            network = ip_network(prefix)
            size = network.num_addresses
            if size >= 65536:
                chunk = 65536
            else:
                chunk = size

            i = 1
            for ip in network:
                bulk.append('(uuid(), "%s", 0x%s)' %
                            (pool_id, ip.packed.hex(),))
                if i == chunk:
                    try:
                        crsr.execute('INSERT INTO calabiyau_ippool' +
                                     ' (id, pool_id, framedipaddress)' +
                                     ' VALUES' +
                                     ' %s' % ", ".join(bulk))
                        crsr.commit()
                    except SQLIntegrityError as e:
                        log.warning(e)
                    i = 1
                    bulk = []
                i += 1


@retry()
def delete_pool(msg):
    MPLogger(__name__)

    pool_id = msg['pool_id']
    prefix = msg['prefix']
    with dbw() as conn:
        with conn.cursor() as crsr:
            network = ip_network(prefix)
            size = network.num_addresses
            start = network[0].packed
            end = network[size-1].packed
            crsr.execute('DELETE FROM calabiyau_ippool' +
                         ' WHERE pool_id = "%s"' % pool_id +
                         ' AND framedipaddress BETWEEN %s AND %s',
                         (start, end,))
            crsr.commit()


def clear_nas_sessions(msg):
    MPLogger(__name__)
    nas_id = msg['nas_id']
    with db() as conn:
        result = conn.execute('SELECT' +
                              ' calabiyau_session.id AS id' +
                              ',calabiyau_session.user_id AS user_id' +
                              ',INET6_NTOA(calabiyau_session' +
                              '.nasipaddress) AS nas' +
                              ',INET6_NTOA(calabiyau_session' +
                              '.framedipaddress) AS ip' +
                              ',calabiyau_session.username AS username' +
                              ',calabiyau_session.acctsessionid' +
                              ' AS acctsessionid' +
                              ',calabiyau_session.acctupdated AS acctupdated' +
                              ' FROM calabiyau_session' +
                              ' INNER JOIN calabiyau_nas' +
                              ' ON calabiyau_session.nasipaddress' +
                              ' = calabiyau_nas.server' +
                              ' WHERE calabiyau_nas.id = %s' +
                              ' AND accttype != "stop"',
                              nas_id).fetchall()

        for session in result:
            session_id = session['id']
            nas = session['nas']
            user_id = session['user_id']
            ip = session['ip']
            username = session['username']
            updated = session['acctupdated']
            nas_session = session['acctsessionid']
            secret = get_nas_secret(session['nas'])

            pod(nas, secret, username, nas_session)

            conn.execute('DELETE FROM calabiyau_session' +
                         ' WHERE id = %s'
                         ' AND acctupdated = %s',
                         (session_id, updated,))
            conn.execute('UPDATE calabiyau_ippool' +
                         ' SET expiry_time = NULL' +
                         ' WHERE user_id = %s' +
                         ' AND framedipaddress = INET6_ATON(%s)',
                         (user_id, ip,))
            conn.commit()


def disconnect_session(msg):
    MPLogger(__name__)
    session_id = msg['session_id']
    with db() as conn:
        result = conn.execute('SELECT' +
                              ' INET6_NTOA(nasipaddress) as nas' +
                              ',INET6_NTOA(framedipaddress) as ip' +
                              ',user_id' +
                              ',acctsessionid' +
                              ',acctupdated' +
                              ' FROM calabiyau_session' +
                              ' WHERE id = %s',
                              session_id).fetchone()
        if result:
            nas = result['nas']
            ip = result['ip']
            user_id = result['user_id']
            username = get_username(user_id)
            updated = result['acctupdated']
            nas_session = result['acctsessionid']
            secret = get_nas_secret(result['nas'])

            pod(nas, secret, username, nas_session)

            conn.execute('DELETE FROM calabiyau_session' +
                         ' WHERE id = %s'
                         ' AND acctupdated = %s',
                         (session_id, updated,))
            conn.execute('UPDATE calabiyau_ippool' +
                         ' SET expiry_time = NULL' +
                         ' WHERE user_id = %s' +
                         ' AND framedipaddress = INET6_ATON(%s)',
                         (user_id, ip,))
            conn.commit()


def disconnect_user(msg):
    MPLogger(__name__)
    user_id = msg['user_id']
    username = msg['username']
    with db() as conn:
        result = conn.execute('SELECT' +
                              ' id' +
                              ',INET6_NTOA(nasipaddress) as nas' +
                              ',INET6_NTOA(framedipaddress) as ip' +
                              ',user_id' +
                              ',acctsessionid' +
                              ',acctupdated' +
                              ' FROM calabiyau_session' +
                              ' WHERE user_id = %s' +
                              ' AND accttype != "stop"',
                              user_id).fetchall()

        for session in result:
            session_id = session['id']
            nas = session['nas']
            ip = session['ip']
            updated = session['acctupdated']
            nas_session = session['acctsessionid']
            secret = get_nas_secret(session['nas'])

            pod(nas, secret, username, nas_session)

            conn.execute('DELETE FROM calabiyau_session' +
                         ' WHERE id = %s'
                         ' AND acctupdated = %s',
                         (session_id, updated,))
            conn.execute('UPDATE calabiyau_ippool' +
                         ' SET expiry_time = NULL' +
                         ' WHERE user_id = %s' +
                         ' AND framedipaddress = INET6_ATON(%s)',
                         (user_id, ip,))
            conn.commit()


@register.resource('system', '/manager')
def manager(req, resp):
    try:
        procs = []
        mplog = MPLogger('__main__')
        mplog.receive()

        mb = MBServer('subscriber',
                      {'radius_accounting': radius_acct,
                       'append_pool': append_pool,
                       'delete_pool': delete_pool,
                       'disconnect_session': disconnect_session,
                       'disconnect_user': disconnect_user,
                       'clear_nas_sessions': clear_nas_sessions},
                      cpu_count() * 4,
                      16)
        mb.start()

        # Additional processes
        procs.append((Process(target=purge_sessions,
                              name="session purger"),
                      purge_sessions,))

        for proc, target in procs:
            proc.start()

        def end(sig):
            for proc, target in procs:
                proc.terminate()

            mb.stop()
            mplog.close()
            exit()

        sig = GracefulKiller(end)

        while True:
            if not sig.killed:
                mb.check()
                for process in procs:
                    proc, target = process
                    if not proc.is_alive():
                        proc.join()
                        procs.remove(process)
                        new = Process(target=target,
                                      name=proc.name,)
                        log.critical('Restarting process %s' % proc.name)
                        procs.append((new, target,))
                        new.start()
                time.sleep(10)

        if not sig.killed:
            end(None)

    except (KeyboardInterrupt, SystemExit):
        end(None)
