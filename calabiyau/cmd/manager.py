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
from multiprocessing import Process, cpu_count

from luxon import register
from luxon import MBServer
from luxon import MPLogger
from luxon import GetLogger
from luxon import dbw
from luxon.utils.mysql import retry
from luxon.exceptions import SQLIntegrityError
#from pyipcalc import IPNetwork

from calabiyau.msgbus.radius.acct import acct as radius_acct

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

    pool_id = msg['id']
    prefix = msg['prefix']
    with dbw() as conn:
        with conn.cursor() as crsr:
            for ip in IPNetwork(prefix):
                try:
                    crsr.execute('INSERT INTO calabiyau_ippool' +
                                 ' (id, pool_id, framedipaddress)' +
                                 ' VALUES' +
                                 ' (uuid()), %s, %s)',
                                 (pool_id, ip.first(),))
                except SQLIntegrityError as e:
                    log.warning(e)
            crsr.commit()


@retry()
def delete_pool(msg):
    log = MPLogger(__name__)

    pool_id = msg['id']
    prefix = msg['prefix']
    with dbw() as conn:
        with conn.cursor() as crsr:
            for ip in IPNetwork(prefix):
                try:
                    conn.execute('DELETE FROM calabiyau_ippool' +
                                 ' WHERE pool_id = %s' +
                                 ' and framedipaddress = %s',
                                 (pool_id, ip.first(),))
                except SQLIntegrityError as e:
                    log.warning(e)
            crsr.commit()


@register.resource('system', '/manager')
def manager(req, resp):
    try:
        procs = []
        mplog = MPLogger('__main__')
        mplog.receive()

        mb = MBServer('calabiyau',
                      {'radius_accounting': radius_acct,
                       'append_pool': append_pool,
                       'delete_pool': delete_pool},
                      cpu_count() * 4,
                      16)
        mb.start()

        # Additional processes
        procs.append((Process(target=purge_sessions,
                              name="session purger"),
                      purge_sessions,))

        for proc, target in procs:
            proc.start()

        while True:
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

        mplog.close()
        mb.stop()

    except (KeyboardInterrupt, SystemExit):
        for proc, target in procs:
            proc.terminate()

        mb.stop()

        mplog.close()
