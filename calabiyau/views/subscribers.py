# -*- coding: utf-8 -*-
# Copyright (c) 2018-2020 Christiaan Frans Rademan <chris@fwiw.co.za>.
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
from luxon import register
from luxon import router
from luxon.helpers.api import sql_list, obj
# from luxon.utils.hashing import md5sum
from luxon import MBClient

from calabiyau.models.subscribers import calabiyau_subscriber
from calabiyau.helpers.packages import get_package, calc_next_expire

from luxon import GetLogger

log = GetLogger(__name__)


@register.resources()
class Users(object):
    def __init__(self):
        # Services Users
        router.add('GET', '/v1/subscriber/{id}', self.user,
                   tag='services:view')
        router.add('GET', '/v1/subscribers', self.users,
                   tag='services:view')
        router.add('POST', '/v1/subscriber', self.create,
                   tag='services:admin')
        router.add(['PUT', 'PATCH'], '/v1/subscriber/{id}', self.update,
                   tag='services:admin')
        router.add('DELETE', '/v1/subscriber/{id}', self.delete,
                   tag='services:admin')

    def user(self, req, resp, id):
        return obj(req, calabiyau_subscriber, sql_id=id,
                   hide=('password',))

    def users(self, req, resp):
        return sql_list(req,
                        'calabiyau_subscriber',
                        fields=('id',
                                'username',
                                'name',),
                        search={'id': str,
                                'username': str,
                                'name': str})

    def pkg_set(self, req, user):
        if req.json.get('package_id'):
            pkg = get_package(req.json.get('package_id'))
            if user['volume_expire'] is None:
                if pkg['plan'] == 'data':
                    if pkg['volume_span'] and pkg['volume_span'] > 0:
                        if pkg['volume_gb'] and pkg['volume_gb'] > 0:
                            user['volume_expire'] = calc_next_expire(
                                pkg['volume_metric'],
                                pkg['volume_span'])
                        else:
                            user['volume_expire'] = None
                    else:
                        user['volume_expire'] = None
                else:
                    user['volume_expire'] = None

            if user['package_expire'] is None:
                if pkg['package_span'] and pkg['package_span'] > 0:
                    user['package_expire'] = calc_next_expire(
                        pkg['package_metric'],
                        pkg['package_span'])
                else:
                    user['package_expire'] = None

    def create(self, req, resp):
        user = obj(req, calabiyau_subscriber,
                   hide=('password',))

        self.pkg_set(req, user)

        # clear text password needed for CHAP
        # if req.json.get('password'):
        #    user['password'] = md5sum(req.json['password'])

        user.commit()
        return user

    def update(self, req, resp, id):
        user = obj(req, calabiyau_subscriber, sql_id=id,
                   hide=('password',))

        # clear text password needed for CHAP
        # if req.json.get('password'):
        #    user['password'] = md5sum(req.json['password'])

        self.pkg_set(req, user)

        if req.json.get('enabled') and user['enabled'] is False:
            with MBClient('subscriber') as mb:
                mb.send('disconnect_user', {'user_id': user['id'],
                                            'username': user['username']})

        user.commit()
        return user

    def delete(self, req, resp, id):
        user = obj(req, calabiyau_subscriber, sql_id=id)
        with MBClient('subscriber') as mb:
            mb.send('disconnect_user', {'user_id': user['id'],
                                        'username': user['username']})
        user.commit()
