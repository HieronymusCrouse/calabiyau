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

from luxon import GetLogger

log = GetLogger(__name__)


def get_user(db, nas_ip, username):
    with db.cursor() as crsr:
        crsr.execute('SELECT' +
                     ' calabiyau_subscriber.id as id,' +
                     ' calabiyau_subscriber.username as username,' +
                     ' calabiyau_subscriber.password as password,' +
                     ' calabiyau_subscriber.package_id as package_id,' +
                     ' calabiyau_subscriber.ctx as ctx,' +
                     ' calabiyau_subscriber.static_ip4 as static_ip4,' +
                     ' calabiyau_subscriber.volume_expire as volume_expire,' +
                     ' calabiyau_subscriber.volume_used_bytes' +
                     ' as volume_used_bytes,' +
                     ' calabiyau_subscriber.volume_used' +
                     ' as volume_used,' +
                     ' calabiyau_subscriber.package_expire' +
                     ' as package_expire,' +
                     ' calabiyau_package.plan as plan,' +
                     ' calabiyau_package.simultaneous as simultaneous,' +
                     ' calabiyau_package.pool_id as pool_id,' +
                     ' calabiyau_package.package_span as package_span,' +
                     ' calabiyau_package.volume_gb as volume_gb,' +
                     ' calabiyau_package.volume_span as volume_span,' +
                     ' calabiyau_package.volume_repeat as volume_repeat,' +
                     ' calabiyau_package.volume_metric as volume_metric,' +
                     ' calabiyau_nas.virtual_id as virtual_id,' +
                     ' calabiyau_nas.nas_type as nas_type,' +
                     ' calabiyau_nas.secret as nas_secret,' +
                     ' calabiyau_subscriber.enabled as enabled' +
                     ' FROM calabiyau_package' +
                     ' INNER JOIN calabiyau_subscriber' +
                     ' ON calabiyau_subscriber.package_id' +
                     ' = calabiyau_package.id' +
                     ' INNER JOIN calabiyau_nas' +
                     ' ON calabiyau_package.virtual_id' +
                     ' = calabiyau_nas.virtual_id' +
                     ' WHERE calabiyau_nas.server = %s' +
                     ' AND calabiyau_subscriber.username = %s',
                     (nas_ip,
                      username,))
        user = crsr.fetchone()
        crsr.commit()
        return user


def require_attributes(ctx, fr, attributes):
    for attribute in attributes:
        if attribute not in fr:
            log.error("Require '%s' in %s-request"
                      % (attribute, ctx,))
            return False
    return True


def parse_fr(fr):
    return dict(fr)


def update_ip(db, user, fr):
    with db.cursor() as crsr:
        if 'Framed-IP-Address' not in fr:
            return None

        crsr.execute('SELECT id FROM calabiyau_ippool' +
                     ' WHERE pool_id = %s AND' +
                     ' framedipaddress = %s' +
                     ' FOR UPDATE',
                     (user['pool_id'], fr['Framed-IP-Address'],))

        if (fr['Acct-Status-Type'] == 'Interim-Update' or
                fr['Acct-Status-Type'] == 'Start'):
            crsr.execute('UPDATE calabiyau_ippool SET' +
                         ' expiry_time = NOW() +' +
                         ' INTERVAL 86400 SECOND' +
                         ' WHERE pool_id = %s AND' +
                         ' framedipaddress = %s AND' +
                         ' expiry_time is not NULL',
                         (user['pool_id'], fr['Framed-IP-Address'],))
        elif fr['Acct-Status-Type'] == 'Stop':
            crsr.execute('UPDATE calabiyau_ippool SET' +
                         ' expiry_time = NULL' +
                         ' WHERE pool_id = %s AND' +
                         ' framedipaddress = %s',
                         (user['pool_id'], fr['Framed-IP-Address'],))

        crsr.commit()


def format_attributes(attributes):
    result = []
    for attribute in attributes:
        result.append((attribute['attribute'], attribute['value'],))
    return result


def get_attributes(crsr, user, ctx):
    crsr.execute('SELECT attribute, value FROM calabiyau_package_attr' +
                 ' WHERE package_id = %s AND ctx = %s' +
                 ' AND nas_type = %s',
                 (user['package_id'],
                  ctx,
                  user['nas_type'],))
    attributes = crsr.fetchall()
    return format_attributes(attributes)
