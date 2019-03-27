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
from luxon import db
from luxon import dbw
from luxon import GetLogger
from luxon.utils.mysql import retry
from luxon.utils.system import execute
from luxon.utils.files import rm
from luxon.utils.timezone import (calc_next_expire,
                                  utc,
                                  parse_datetime,
                                  now)
from calabiyau.msgbus.radius.helpers import (parse_fr,
                                             require_attributes,
                                             get_user,
                                             get_attributes,
                                             update_ip)

log = GetLogger(__name__)


@retry()
def do_acct(db, fr, dt, user, status):
    user_id = user['id']
    nas_session_id = fr['Acct-Session-Id']
    unique_session_id = fr['Acct-Unique-Session-Id']
    input_octets = int(fr.get('Acct-Input-Octets64', 0))
    output_octets = int(fr.get('Acct-Output-Octets64', 0))

    with db.cursor() as crsr:
        #######################################
        # GET USAGE IN & OUT FOR USER SESSION #
        #######################################
        crsr.execute("SELECT" +
                     " id," +
                     " acctstarttime," +
                     " acctinputoctets," +
                     " acctoutputoctets," +
                     " acctuniqueid," +
                     " acctstarttime," +
                     " acctupdated," +
                     " accttype" +
                     " FROM calabiyau_session" +
                     ' WHERE acctuniqueid = %s' +
                     ' LIMIT 1' +
                     ' FOR UPDATE',
                     (unique_session_id,))
        session = crsr.fetchone()
        if session and (utc(session['acctupdated']) >= dt or
                        session['accttype'] == 'stop'):
            crsr.commit()
            return (0, 0,)

        #############################################
        # CHECK IF ACCOUNTING FOR TODAY FOR USER_ID #
        #############################################
        crsr.execute("SELECT" +
                     " id" +
                     " FROM calabiyau_accounting" +
                     " WHERE user_id = %s" +
                     " AND date(today) = date(now())" +
                     " FOR UPDATE",
                     (user_id,))

        if (status == 'interim-update' or
                status == 'start' or status == 'stop'):
            ######################################################
            # CREATE/UPDATE SESSION WITH INPUT AND OUTPUT OCTETS #
            ######################################################
            crsr.execute("INSERT INTO calabiyau_session" +
                         " (id," +
                         " user_id," +
                         " acctsessionid," +
                         " acctuniqueid," +
                         " nasipaddress," +
                         " nasportid," +
                         " nasport," +
                         " nasporttype," +
                         " calledstationid," +
                         " callingstationid," +
                         " servicetype," +
                         " framedprotocol," +
                         " framedipaddress," +
                         " acctinputoctets," +
                         " acctoutputoctets," +
                         " acctstarttime," +
                         " acctupdated," +
                         " processed," +
                         " accttype)" +
                         " VALUES" +
                         " (uuid(), %s, %s, %s, %s, %s, %s, %s, %s," +
                         " %s, %s, %s, %s, %s, %s, %s, %s, now(), %s)" +
                         " ON DUPLICATE KEY UPDATE" +
                         " acctsessionid = %s," +
                         " nasipaddress = %s," +
                         " nasportid = %s," +
                         " nasport = %s," +
                         " nasporttype = %s," +
                         " calledstationid = %s," +
                         " callingstationid = %s," +
                         " servicetype = %s," +
                         " framedprotocol = %s," +
                         " framedipaddress = %s," +
                         " acctinputoctets = %s," +
                         " acctoutputoctets = %s," +
                         " acctupdated = %s," +
                         " processed = now()," +
                         " accttype = %s",
                         (user_id,
                          nas_session_id,
                          unique_session_id,
                          fr['NAS-IP-Address'],
                          fr.get('NAS-Port-ID'),
                          fr.get('NAS-Port'),
                          fr.get('NAS-Port-Type'),
                          fr.get('Called-Station-Id'),
                          fr.get('Calling-Station-Id'),
                          fr.get('Service-Type'),
                          fr.get('Framed-Protocol'),
                          fr.get('Framed-IP-Address'),
                          input_octets,
                          output_octets,
                          dt,
                          dt,
                          status,
                          nas_session_id,
                          fr['NAS-IP-Address'],
                          fr.get('NAS-Port-ID'),
                          fr.get('NAS-Port'),
                          fr.get('NAS-Port-Type'),
                          fr.get('Called-Station-Id'),
                          fr.get('Calling-Station-Id'),
                          fr.get('Service-Type'),
                          fr.get('Framed-Protocol'),
                          fr.get('Framed-IP-Address'),
                          input_octets,
                          output_octets,
                          dt,
                          status,))

        ####################################
        # RECORD USAGE IN ACCOUNTING TABLE #
        ####################################
        if not session:
            # IF NEW SESSION
            prev_acctinputoctets = 0
            prev_acctoutputoctets = 0
        else:
            # IF EXISTING SESSION
            # USE PREVIOUS VALUES TO DETERMINE NEW VALUES FOR TODAY
            prev_acctinputoctets = session['acctinputoctets']
            prev_acctoutputoctets = session['acctoutputoctets']

        if (input_octets >= prev_acctinputoctets and
                output_octets >= prev_acctoutputoctets):

            input_octets = (input_octets -
                            prev_acctinputoctets)
            output_octets = (output_octets -
                             prev_acctoutputoctets)

            # INSERT/UPDATE ACCOUNTING RECORD
            crsr.execute('INSERT INTO calabiyau_accounting' +
                         ' (id, user_id, today, acctinputoctets,' +
                         ' acctoutputoctets)' +
                         ' VALUES' +
                         ' (uuid(), %s, curdate(), %s, %s)' +
                         ' ON DUPLICATE KEY UPDATE' +
                         ' acctinputoctets = acctinputoctets + %s,' +
                         ' acctoutputoctets = acctoutputoctets + %s',
                         (user_id,
                          input_octets,
                          output_octets,
                          input_octets,
                          output_octets,))

        crsr.commit()

        return (input_octets, output_octets,)


def coa(crsr, user, ctx, fr, secret, status):
    if (status == 'interim-update' or
            status == 'start'):

        nas_session_id = fr['Acct-Session-Id']
        unique_session_id = fr['Acct-Unique-Session-Id']
        nas_ip_address = fr['NAS-IP-Address']

        ctx_values = ['activate-coa',
                      'deactivate-coa']

        attributes = get_attributes(crsr, user, ctx_values[ctx])
        if not attributes:
            # SEND POD
            with open('/tmp/pod_%s.txt' % unique_session_id, 'w') as pod:
                pod.write('Acct-Session-Id = "%s"\n' % nas_session_id)
                pod.write('User-Name = "%s"\n' % user['username'])
                pod.write('NAS-IP-Address = %s\n' % nas_ip_address)
            try:
                execute(['/usr/bin/env',
                         'radclient',
                         '-f',
                         '/tmp/pod_%s.txt' % unique_session_id,
                         '-x',
                         '%s:3799' % nas_ip_address,
                         'disconnect',
                         secret])
                crsr.execute('UPDATE calabiyau_session' +
                             ' SET ctx = %s' +
                             ' WHERE acctuniqueid = %s',
                             (ctx, unique_session_id,))
            except Exception:
                pass

            rm('/tmp/pod_%s.txt' % unique_session_id)
        else:
            # SEND COA
            with open('/tmp/coa_%s.txt' % unique_session_id, 'w') as pod:
                pod.write('Acct-Session-Id = "%s"\n' % nas_session_id)
                pod.write('User-Name = "%s"\n' % user['username'])
                pod.write('NAS-IP-Address = %s\n' % nas_ip_address)
                for attribute in attributes:
                    pod.write('%s = %s\n' % (attribute[0], attribute[1],))
            try:
                execute(['/usr/bin/env',
                         'radclient',
                         '-f',
                         '/tmp/coa_%s.txt' % unique_session_id,
                         '-x',
                         '%s:3799' % nas_ip_address,
                         'coa',
                         secret])
                crsr.execute('UPDATE calabiyau_session' +
                             ' SET ctx = %s' +
                             ' WHERE acctuniqueid = %s',
                             (ctx, unique_session_id,))
            except Exception:
                pass
            rm('/tmp/coa_%s.txt' % unique_session_id)


@retry()
def usage(db, fr, user, input_octets=0, output_octets=0, status="start"):
    # Return Values
    # 0 All good.
    # 1 Deactivate Subscriber
    unique_session_id = fr['Acct-Unique-Session-Id']
    user_id = user['id']
    nas_secret = user['nas_secret']

    # Combined input/output usage for session
    combined = input_octets + output_octets

    utc_datetime = now()

    with db.cursor() as crsr:
        ####################
        # GET USER SESSION #
        ####################
        crsr.execute("SELECT" +
                     " id," +
                     " ctx" +
                     " FROM calabiyau_session" +
                     ' WHERE acctuniqueid = %s' +
                     ' LIMIT 1' +
                     ' FOR UPDATE',
                     (unique_session_id,))
        session = crsr.fetchone()
        session_ctx = session['ctx']

        if user['package_span'] and user['package_span'] > 0:
            if (utc(user['package_expire']) and
                    utc_datetime > utc(user['package_expire'])):
                if session_ctx != 1:
                    coa(crsr, user, 1, fr, nas_secret, status)
                crsr.commit()
                return 1

        crsr.execute('SELECT * FROM calabiyau_subscriber' +
                     ' WHERE id = %s' +
                     ' FOR UPDATE',
                     (user_id,))
        locked_user = crsr.fetchone()
        if user and locked_user:
            # IF DATA PLAN NOT UNCAPPED
            if user['plan'] == 'data':
                ######################
                # CHECK PACKAGE DATA #
                ######################
                volume_used_bytes = locked_user['volume_used_bytes'] + combined
                pkg_volume_used = locked_user['volume_used']
                if user['volume_gb']:
                    package_volume_bytes = (user['volume_gb'] *
                                            1024 * 1024 * 1024)
                else:
                    package_volume_bytes = 0

                if utc(locked_user['volume_expire']) < utc_datetime:
                    if user['volume_repeat']:
                        log.info('Package data reloaded (%s)'
                                 % user['username'])
                        new_expire = calc_next_expire(user['volume_metric'],
                                                      user['volume_span'],
                                                      utc_datetime)
                        crsr.execute("UPDATE calabiyau_subscriber" +
                                     " SET volume_expire = %s," +
                                     " volume_used_bytes = 0," +
                                     " volume_used = 0," +
                                     " ctx = 0" +
                                     " WHERE id = %s",
                                     (new_expire, user['id'],))
                        pkg_volume_used = 0
                        if session_ctx != 0:
                            coa(crsr, user, 0, fr, nas_secret, status)
                        crsr.commit()
                        return 0
                    else:
                        crsr.execute("UPDATE calabiyau_subscriber" +
                                     " SET volume_expire = %s," +
                                     " volume_used_bytes = 0," +
                                     " volume_used = 1," +
                                     " ctx = 1" +
                                     " WHERE id = %s",
                                     (new_expire, user['id'],))
                        pkg_volume_used = 1
                        log.info('Package data expired (%s)'
                                 % user['username'])

                if (not pkg_volume_used and
                        volume_used_bytes > package_volume_bytes):
                    crsr.execute("UPDATE calabiyau_subscriber" +
                                 " SET volume_used_bytes = 0," +
                                 " volume_used = 1," +
                                 " ctx = 1" +
                                 " WHERE id = %s",
                                 (user_id,))
                    log.info('Package data depleted (%s)'
                             % user['username'])
                elif (not pkg_volume_used and
                        volume_used_bytes <= package_volume_bytes):
                    crsr.execute("UPDATE calabiyau_subscriber" +
                                 " SET volume_used_bytes = " +
                                 " volume_used_bytes + %s," +
                                 " ctx = 0" +
                                 " WHERE id = %s",
                                 (combined, user_id,))
                    if session_ctx != 0:
                        coa(crsr, user, 0, fr, nas_secret, status)
                    crsr.commit()
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

                    if utc(topup['volume_expire']) < utc_datetime:
                        if topup['volume_repeat']:
                            log.auth('Topup renew (%s, %s Gb, %s)' %
                                     (user['username'],
                                      topup['volume_gb'],
                                      topup['creation_time'],))
                            new_expire = calc_next_expire(
                                topup['volume_metric'],
                                topup['volume_span'],
                                utc_datetime)

                            crsr.execute("UPDATE calabiyau_topup" +
                                         " SET volume_expire = %s" +
                                         " WHERE id = %s",
                                         (new_expire, topup['id'],))
                            crsr.execute("UPDATE calabiyau_subscriber" +
                                         " SET volume_used_bytes = 0," +
                                         " ctx = 0" +
                                         " WHERE id = %s",
                                         (user_id,))
                            if session_ctx != 0:
                                coa(crsr, user, 0, fr, nas_secret, status)
                            crsr.commit()
                            return 0
                        else:
                            log.auth('Topup expired (%s, %s Gb, %s)' %
                                     (user['username'],
                                      topup['volume_gb'],
                                      topup['creation_time'],))
                            crsr.execute("UPDATE calabiyau_subscriber" +
                                         " SET volume_used_bytes = 0," +
                                         " ctx = 0" +
                                         " WHERE id = %s",
                                         (user_id,))
                            crsr.execute('DELETE FROM' +
                                         ' calabiyau_topup' +
                                         ' WHERE id = %s',
                                         (topup['id'],))
                    else:
                        if volume_used_bytes < topup_volume_bytes:
                            crsr.execute("UPDATE calabiyau_subscriber" +
                                         " SET volume_used_bytes = " +
                                         " volume_used_bytes + %s," +
                                         " ctx = 0" +
                                         " WHERE id = %s",
                                         (combined, user_id,))
                            if session_ctx != 0:
                                coa(crsr, user, 0, fr, nas_secret, status)
                            crsr.commit()
                            return 0
                        else:
                            log.auth('Topup depleted (%s, %s Gb, %s)' %
                                     (user['username'],
                                      topup['volume_gb'],
                                      topup['creation_time'],))
                            crsr.execute("UPDATE calabiyau_subscriber" +
                                         " SET volume_used_bytes = 0," +
                                         " ctx = 0" +
                                         " WHERE id = %s",
                                         (user_id,))
                            crsr.execute('DELETE FROM' +
                                         ' calabiyau_topup' +
                                         ' WHERE id = %s',
                                         (topup['id'],))

                if session_ctx != 1:
                    coa(crsr, user, 1, fr, nas_secret, status)
                crsr.commit()
                return 1
            else:
                if session_ctx != 0:
                    coa(crsr, user, 0, fr, nas_secret, status)
                crsr.commit()
                return 0
        if session_ctx != 1:
            coa(crsr, user, 1, fr, nas_secret, status)
        crsr.commit()
        return 1


def acct(msg):
    fr = parse_fr(msg.get('fr', ()))
    status = fr.get('Acct-Status-Type', 'start').lower()
    dt = utc(parse_datetime(msg.get('datetime', None)))
    diff = (now()-dt).total_seconds()

    if diff > 60:
        log.error('Processing radius accounting message older' +
                  ' than 60 seconds. Age(%s)' % diff)

    if not require_attributes('accounting', fr, ['User-Name',
                                                 'NAS-IP-Address',
                                                 'Acct-Status-Type',
                                                 'Acct-Session-Id',
                                                 'Acct-Unique-Session-Id',
                                                 'Acct-Input-Octets64',
                                                 'Acct-Output-Octets64']):
        return False

    with db() as conn:
        with dbw() as connw:
            user = get_user(conn,
                            fr['NAS-IP-Address'],
                            fr['User-Name'])
            if not user:
                log.debug("user '%s' not found"
                          % (fr['User-Name'],))
                return False

            input_octets, output_octets = do_acct(connw, fr, dt, user, status)
            usage(connw, fr, user, input_octets, output_octets, status)

            if not user['static_ip4'] and user['pool_id']:
                update_ip(dbw, user, fr)

    return True
