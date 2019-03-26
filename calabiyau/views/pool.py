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
from luxon import register
from luxon import router
from luxon import MBClient
from luxon.helpers.access import validate_access
from luxon.helpers.api import sql_list, obj
from pyipcalc import IPNetwork

from subscriber.models.pool import subscriber_pool

from luxon import GetLogger

log = GetLogger(__name__)


@register.resources()
class Pool(object):
    def __init__(self):
        # Normal Tachyonic uers.
        router.add('GET', '/v1/pool/{id}', self.pool,
                   tag='services')
        router.add('GET', '/v1/pool', self.pools,
                   tag='services')
        router.add('POST', '/v1/pool', self.create,
                   tag='services')
        router.add(['PUT', 'PATCH'], '/v1/pool/{id}', self.update,
                   tag='services')
        router.add('DELETE', '/v1/pool/{id}', self.delete,
                   tag='services')
        router.add('GET', '/v1/pool/{id}/ips', self.ips,
                   tag='services')
        router.add('POST', '/v1/pool/{id}/add_prefix', self.add_prefix,
                   tag='services')
        router.add('DELETE', '/v1/pool/{id}/rm_prefix', self.rm_prefix,
                   tag='services')

    def pool(self, req, resp, id):
        return obj(req, subscriber_pool, sql_id=id,
                   hide=('password',))

    def pools(self, req, resp):
        return sql_list(req, 'subscriber_pool',
                        ('id', 'pool_name',))

    def create(self, req, resp):
        pool = obj(req, subscriber_pool)
        pool.commit()
        return pool

    def update(self, req, resp, id):
        pool = obj(req, subscriber_pool, sql_id=id)
        pool.commit()
        return pool

    def delete(self, req, resp, id):
        pool = obj(req, subscriber_pool, sql_id=id)
        pool.commit()

    def ips(self, req, resp, id):
        pool = obj(req, subscriber_pool, sql_id=id)
        return sql_list(req, 'subscriber_ippool',
                        ('id',
                         'framedipaddress',
                         'nasipaddress',
                         'expiry_time',
                         'username',),
                        where={'pool_name': pool['pool_name']})

    def add_prefix(self, req, resp, id):
        pool = subscriber_pool()
        pool.sql_id(id)
        validate_access(req, pool)

        if not req.json.get('prefix'):
            raise ValueError('Prefix Required')

        prefix = IPNetwork(req.json['prefix']).prefix()

        with MBClient('subscriber') as mb:
            msg = {'id': pool['id'],
                   'prefix': prefix,
                   'domain': req.context_domain}
            mb.send('append_pool', msg)

    def rm_prefix(self, req, resp, id):
        pool = subscriber_pool()
        pool.sql_id(id)
        validate_access(req, pool)

        if not req.json.get('prefix'):
            raise ValueError('Prefix Required')

        prefix = IPNetwork(req.json['prefix']).prefix()

        with MBClient('subscriber') as mb:
            msg = {'id': pool['id'],
                   'prefix': prefix,
                   'domain': req.context_domain}
            mb.send('delete_pool', msg)
