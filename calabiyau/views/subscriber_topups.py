# -*- coding: utf-8 -*-
# Copyright (c) 2018-2019 Dave Kruger.
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
from luxon import db
from luxon.helpers.api import sql_list, obj

from calabiyau.helpers.packages import calc_next_expire
from calabiyau.models.topups import calabiyau_topup


@register.resources()
class TopUps(object):
    def __init__(self):
        router.add('GET', '/v1/subscriber-topup/{id}', self.topup,
                   tag='services:view')
        router.add('GET', '/v1/subscriber-topups', self.topups,
                   tag='services:view')
        router.add('POST', '/v1/subscriber-topup', self.create,
                   tag='services:admin')
        router.add(['PUT', 'PATCH'], '/v1/subscriber-topup/{id}', self.update,
                   tag='services:admin')
        router.add('DELETE', '/v1/subscriber-topup/{id}', self.delete,
                   tag='services:admin')

    def topup(self, req, resp, id):
        return obj(req, calabiyau_topup, sql_id=id)

    def topups(self, req, resp):
        return sql_list(req, 'subscriber_topup',
                        ('id', 'user_id', 'volume_gb','volume_metric',
                         'volume_span','volume_repeat', 'volume_expire'), )

    def create(self, req, resp):
        topup = obj(req, calabiyau_topup)

        topup.commit()

        if req.json.get('volume_metric') and req.json.get('volume_span'):
            volume_expire = calc_next_expire(
                req.json.get('volume_metric'),
                req.json.get('volume_span'))

            sql = 'UPDATE subscriber_topup SET volume_expire=? WHERE id=?'
            with db() as conn:
                conn.execute(sql, (volume_expire, topup['id'],))
                conn.commit()

            topup = topup.dict
            topup['volume_expire'] = volume_expire

        return topup

    def update(self, req, resp, id):
        topup = obj(req, calabiyau_topup, sql_id=id)

        topup.commit()
        return topup

    def delete(self, req, resp, id):
        topup = obj(req, calabiyau_topup, sql_id=id)

        topup.commit()
