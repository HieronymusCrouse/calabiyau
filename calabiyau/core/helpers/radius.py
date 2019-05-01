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
import base64
import pickle

from luxon.utils.mysql import retry

from calabiyau.helpers.radius import dictionary

dictionary = dictionary()


def get_user(crsr, client, nas_ip, username):
    crsr.execute('SELECT' +
                 ' calabiyau_subscriber.id as id,' +
                 ' calabiyau_subscriber.username as username,' +
                 ' calabiyau_subscriber.password as password,' +
                 ' calabiyau_subscriber.package_id as package_id,' +
                 ' calabiyau_subscriber.ctx as ctx,' +
                 ' INET6_NTOA(calabiyau_subscriber.static_ip4)' +
                 ' as static_ip4,' +
                 ' calabiyau_subscriber.volume_expire as volume_expire,' +
                 ' calabiyau_subscriber.volume_used_bytes' +
                 ' as volume_used_bytes,' +
                 ' calabiyau_subscriber.volume_used' +
                 ' as volume_used,' +
                 ' calabiyau_subscriber.package_expire' +
                 ' as package_expire,' +
                 ' calabiyau_package.name as package,' +
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
                 ' WHERE (calabiyau_nas.server = INET6_ATON(%s)' +
                 ' OR calabiyau_nas.server = INET6_ATON(%s))' +
                 ' AND calabiyau_subscriber.username = %s',
                 (client,
                  nas_ip,
                  username,))
    user = crsr.fetchone()
    return user


def format_attributes(attributes):
    result = {}
    for attribute in attributes:
        attrname = attribute['attribute']
        if attribute['tag']:
            attrname += ':%s' % attribute['tag']
        if attrname not in result:
            result[attrname] = []
        result[attrname].append(attribute['value'])
    return result


def get_attributes(crsr, user, ctx):
    crsr.execute('SELECT attribute, tag, value FROM calabiyau_package_attr' +
                 ' WHERE package_id = %s AND ctx = %s' +
                 ' AND nas_type = %s',
                 (user['package_id'],
                  ctx,
                  user['nas_type'],))
    attributes = crsr.fetchall()
    return format_attributes(attributes)


def has_session(crsr, user):
    crsr.execute("SELECT count(id) as qty" +
                 " FROM calabiyau_session" +
                 " WHERE user_id = %s AND" +
                 " accttype != 'stop'",
                 (user['id'],))
    result = crsr.fetchone()
    if result:
        return result['qty']
    else:
        return 0


def get_pool_name(crsr, user):
    crsr.execute('SELECT' +
                 ' pool_name' +
                 ' FROM calabiyau_pool' +
                 ' WHERE id = %s' +
                 ' LIMIT 1',
                 (user['pool_id'], ))
    result = crsr.fetchone()
    if result:
        return result['pool_name']
    return None


def get_ip(db, user):
    with db.cursor() as crsr:
        crsr.execute('SELECT' +
                     ' id' +
                     ', INET6_NTOA(framedipaddress) as framedipaddress' +
                     ' FROM calabiyau_ippool' +
                     ' WHERE pool_id = %s' +
                     ' AND (expiry_time < NOW() OR expiry_time IS NULL)' +
                     ' ORDER BY' +
                     ' (user_id <> %s),' +
                     ' expiry_time' +
                     ' LIMIT 1' +
                     ' FOR UPDATE',
                     (user['pool_id'], user['id'], ))
        ip = crsr.fetchone()
        if ip:
            crsr.execute('UPDATE calabiyau_ippool SET' +
                         ' user_id = %s,' +
                         ' expiry_time = NOW() +' +
                         ' INTERVAL 86400 SECOND' +
                         ' WHERE id = %s',
                         (user['id'], ip['id'],))
            db.commit()
            return ip['framedipaddress']

        db.commit()
        return None


@retry()
def update_ip(db, status, user, pkt):
    with db.cursor() as crsr:
        if 'Framed-IP-Address' not in pkt:
            return None
        crsr.execute('SELECT id FROM calabiyau_ippool' +
                     ' WHERE pool_id = %s AND' +
                     ' framedipaddress = INET6_ATON(%s)' +
                     ' FOR UPDATE',
                     (user['pool_id'], pkt['Framed-IP-Address'][0],))

        if (status == 'interim-update' or
                status == 'start'):
            crsr.execute('UPDATE calabiyau_ippool SET' +
                         ' expiry_time = NOW() +' +
                         ' INTERVAL 86400 SECOND' +
                         ' WHERE pool_id = %s AND' +
                         ' framedipaddress = INET6_ATON(%s) AND' +
                         ' expiry_time is not NULL',
                         (user['pool_id'], pkt['Framed-IP-Address'][0],))
        elif status == 'stop':
            crsr.execute('UPDATE calabiyau_ippool SET' +
                         ' expiry_time = NULL' +
                         ' WHERE pool_id = %s AND' +
                         ' framedipaddress = INET6_ATON(%s)',
                         (user['pool_id'], pkt['Framed-IP-Address'][0],))
        crsr.commit()


def encode_packet(pkt):
    attributes = {}
    for attr in pkt.keys():
        attributes[attr] = pkt[attr]
    return base64.b64encode(pickle.dumps(attributes,
                                         protocol=4))


def decode_packet(pkt):
    return pickle.loads(base64.b64decode(pkt))
