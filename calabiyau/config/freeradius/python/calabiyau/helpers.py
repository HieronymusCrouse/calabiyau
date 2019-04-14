#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2018-2019 Christiaan Frans Rademan, Dave Kruger.
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
import traceback
import md5
import Queue
import json
from datetime import datetime

import pika
import pymysql
from pymysql.constants import COMMAND
import ConfigParser

from calabiyau.logger import Logger
from calabiyau.exceptions import MessageBusError

log = Logger(__name__)


def error_handler(e):
    trace = str(traceback.format_exc())
    log.error(trace)


def config(config_file="/etc/tachyonic/calabiyau.ini"):
    config = ConfigParser.ConfigParser()
    config.read([config_file])

    return config


def parse_fr(fr):
    return dict(fr)


def format_attributes(attributes):
    result = []
    for attribute in attributes:
        result.append((attribute['attribute'],
                       attribute['value'],))
    return result


def require_attributes(ctx, fr, attributes):
    for attribute in attributes:
        if attribute not in fr:
            log.error("subscriber Require '%s' in %s-request"
                      % (attribute, ctx,))
            return False
    return True


def check_password(user_password, md5_hash):
    user_password = str(md5.new(user_password).hexdigest())

    return user_password == md5_hash


class Rmq(object):
    queue = Queue.Queue()
    handles = []

    def __init__(self):

        ini = config()

        try:
            host = ini.get('rabbitmq', 'host')
        except Exception:
            host = '127.0.0.1'

        try:
            port = int(ini.get('rabbitmq', 'port'))
        except Exception:
            port = 5672

        try:
            virtualhost = ini.get('rabbitmq', 'virtualhost')
        except Exception:
            virtualhost = '/'

        try:
            username = ini.get('rabbitmq', 'username')
            password = ini.get('rabbitmq', 'password')
        except Exception:
            username = None
            password = None

        params = [host, port, virtualhost]

        if username:
            params.append(pika.PlainCredentials(username, password))

        self._params = pika.ConnectionParameters(*params)

        self.connection = None
        self.channel = None

    def close(self):
        for conn in Rmq.handles:
            try:
                self.connection.close()
            except Exception:
                pass

    def distribute(self, **kwargs):
        retry = 5
        if self.connection is None:
            raise MessageBusError('not rmq context')

        for i in range(retry):
            try:
                message = json.dumps(kwargs)
                channel = self.channel
                channel.queue_declare(queue="subscriber", durable=True)
                channel.basic_publish(exchange='',
                                      routing_key="subscriber",
                                      body=message,
                                      properties=pika.BasicProperties(
                                         delivery_mode=2,  # msg persistent
                                         content_type='application/json',
                                         content_encoding='utf-8'
                                      ))
                return True
            except pika.exceptions.ChannelClosed as e:
                if i == retry - 1:
                    raise MessageBusError(e)
                self.connection = pika.BlockingConnection(self._params)
                self.channel = self.connection.channel()
            except pika.exceptions.ConnectionClosed as e:
                if i == retry - 1:
                    raise MessageBusError(e)
                self.connection = pika.BlockingConnection(self._params)
                self.channel = self.connection.channel()

    def __enter__(self):
        try:
            self.connection, self.channel = Rmq.queue.get(False)
        except Queue.Empty:
            self.connection = pika.BlockingConnection(self._params)
            self.channel = self.connection.channel()

        return self

    def __exit__(self, type, value, traceback):
        Rmq.queue.put((self.connection, self.channel,))
        self.connection = None


class Db(object):
    all_queue = Queue.Queue()
    wr_queue = Queue.Queue()
    handles = []

    def __init__(self, write=False):
        self._conn = None
        self._write = write

    def __enter__(self):
        try:
            if self._write:
                self._conn = Db.wr_queue.get(False)
                self._ping()
                return self._conn
            else:
                self._conn = Db.all_queue.get(False)
                self._ping()
                return self._conn
        except Queue.Empty:
            ini = config()
            host = ini.get('database', 'host')
            write = ini.get('database', 'write')
            dbname = ini.get('database', 'database')
            username = ini.get('database', 'username')
            password = ini.get('database', 'password')
            if self._write:
                host = write

            self._conn = pymysql.connect(
                host,
                username,
                password,
                dbname,
                cursorclass=pymysql.cursors.DictCursor)

            cursor = self._conn.cursor()
            cursor.execute('SET time_zone = %s', '+00:00')
            self._conn.commit()
            Db.handles.append(self._conn)

            return self._conn

    def __exit__(self, type, value, traceback):
        if self._write:
            Db.wr_queue.put(self._conn)
        else:
            Db.all_queue.put(self._conn)
        self._conn = None

    def _ping(self):
        """Check if the server is alive.

        Auto-Reconnect if not, and return false when reconnecting.
        """
        if self._conn._sock is None:
            self._conn.connect()
            cursor = self._conn.cursor()
            cursor.execute('SET time_zone = %s', '+00:00')
            self._conn.commit()
            return False
        else:
            try:
                self._conn._execute_command(COMMAND.COM_PING, "")
                self._conn._read_ok_packet()
                return True
            except Exception:
                self._conn.connect()
                cursor = self._conn.cursor()
                cursor.execute('SET time_zone = %s', '+00:00')
                self._conn.commit()
                return False

    def close(self):
        for conn in Db.handles:
            try:
                conn.close()
            except Exception:
                pass


def get_pool_name(db, user):
    with db.cursor() as crsr:
        crsr.execute('SELECT' +
                     ' pool_name' +
                     ' FROM calabiyau_pool' +
                     ' WHERE id = %s' +
                     ' LIMIT 1',
                     (user['pool_id'], ))
        result = crsr.fetchone()
        db.commit()
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


def has_session(db, user):
    with db.cursor() as crsr:
        crsr.execute("SELECT id" +
                     " FROM calabiyau_session" +
                     " WHERE user_id = %s AND" +
                     " accttype != 'stop'",
                     (user['id'],))
        db.commit()
        return crsr.fetchone()


def get_attributes(db, user, ctx):
    with db.cursor() as crsr:
        crsr.execute('SELECT attribute, value FROM calabiyau_package_attr' +
                     ' WHERE package_id = %s AND ctx = %s' +
                     ' AND nas_type = %s',
                     (user['package_id'],
                      ctx,
                      user['nas_type'],))
        attributes = crsr.fetchall()
        db.commit()
        return format_attributes(attributes)


def get_user(db, nas_ip, username):
    with db.cursor() as crsr:
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
                     ' calabiyau_subscriber.enabled as enabled' +
                     ' FROM calabiyau_package' +
                     ' INNER JOIN calabiyau_subscriber' +
                     ' ON calabiyau_subscriber.package_id' +
                     ' = calabiyau_package.id' +
                     ' INNER JOIN calabiyau_nas' +
                     ' ON calabiyau_package.virtual_id' +
                     ' = calabiyau_nas.virtual_id' +
                     ' WHERE calabiyau_nas.server = INET6_ATON(%s)' +
                     ' AND calabiyau_subscriber.username = %s',
                     (nas_ip,
                      username,))
        user = crsr.fetchone()
        db.commit()
        return user


def usage(db, user):
    # Return Values
    # 0 All good.
    # 1 Deactivate Subscriber

    user_id = user['id']

    utc_datetime = datetime.utcnow()
    if user['package_span'] and user['package_span'] > 0:
        if (user['package_expire'] and
                utc_datetime > user['package_expire']):
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
            if user['volume_expire'] < utc_datetime:
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
            with db.cursor() as crsr:
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

                    if topup['volume_expire'] < utc_datetime:
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
                db.commit()
                return 1
        else:
            return 0
