# -*- coding: utf-8 -*-
# Copyright (c) 2019-2020 Christiaan Frans Rademan <chris@fwiw.co.za>.
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
from luxon.helpers.api import raw_list, sql_list, obj
from luxon.utils import sql
from luxon import db

from calabiyau.models.subscribers import calabiyau_subscriber

from luxon import GetLogger

log = GetLogger(__name__)


@register.resources()
class Accounting(object):
    def __init__(self):
        # Services Users
        router.add('GET',
                   '/v1/accounting/data/daily/{user_id}',
                   self.data_daily,
                   tag='services:view')

        router.add('GET',
                   '/v1/accounting/data/monthly/{user_id}',
                   self.data_monthly,
                   tag='services:view')

        router.add('GET',
                   '/v1/accounting/data/usage/{user_id}',
                   self.data_usage,
                   tag='services:view')

    def data_daily(self, req, resp, user_id):
        user = obj(req, calabiyau_subscriber, sql_id=user_id)
        f_id = sql.Field('id')
        f_user_id = sql.Field('user_id')
        f_today = sql.Field('today')
        f_acctinputoctets = sql.Field('ROUND(acctinputoctets' +
                                      ' / 1024 / 1024 / 1024, 2)' +
                                      ' AS acctinputoctets')
        f_acctoutputoctets = sql.Field('ROUND(acctoutputoctets' +
                                       ' / 1024 / 1024 / 1024, 2)' +
                                       ' AS acctoutputoctets')
        v_user_id = sql.Value(user['id'])

        select = sql.Select('calabiyau_accounting')
        select.fields = (f_id,
                         f_today,
                         f_acctinputoctets,
                         f_acctoutputoctets,)

        select.where = f_user_id == v_user_id
        select.order_by = f_today('>')
        return sql_list(req,
                        select,
                        limit=32)

    def data_monthly(self, req, resp, user_id):
        user = obj(req, calabiyau_subscriber, sql_id=user_id)
        f_id = sql.Field('id')
        f_user_id = sql.Field('user_id')
        f_today = sql.Field('today')
        f_acctinputoctets = sql.Field('ROUND(SUM(acctinputoctets)' +
                                      ' / 1024 / 1024 / 1024, 2)' +
                                      ' AS acctinputoctets')
        f_acctoutputoctets = sql.Field('ROUND(SUM(acctoutputoctets)' +
                                       ' / 1024 / 1024 / 1024, 2)' +
                                       ' AS acctoutputoctets')
        v_user_id = sql.Value(user['id'])

        select = sql.Select('calabiyau_accounting')
        select.fields = (f_id,
                         f_today,
                         f_acctinputoctets,
                         f_acctoutputoctets,)

        select.where = f_user_id == v_user_id
        select.order_by = f_today('>')
        select.group_by = sql.Field('YEAR(today)'), sql.Field('MONTH(today)')
        return sql_list(req,
                        select,
                        limit=12)

    def data_usage(self, req, resp, user_id):
        content = []
        user = obj(req, calabiyau_subscriber, sql_id=user_id)

        if user['volume_used_bytes']:
            used = user['volume_used_bytes'] / 1024 / 1024 / 1024
        else:
            used = 0

        f_user_id = sql.Field('user_id')
        v_user_id = sql.Value(user['id'])
        f_volume_gb = sql.Field('sum(volume_gb) as volume_gb')

        select = sql.Select('calabiyau_topup')
        select.fields = f_volume_gb
        select.where = f_user_id == v_user_id
        with db() as conn:
            result = conn.execute(select.query, select.values).fetchone()
            if result:
                topups = result['volume_gb']
                if topups is None:
                    topups = 0
            else:
                topups = 0

            if not user['volume_used']:
                f_pkg_id = sql.Field('id')
                v_pkg_id = sql.Value(user['package_id'])
                f_volume_gb = sql.Field('volume_gb')
                select = sql.Select('calabiyau_package')
                select.where = f_pkg_id == v_pkg_id
                result = conn.execute(select.query, select.values).fetchone()
                if result:
                    pkg_volume = result['volume_gb']
                    if pkg_volume is None:
                        pkg_volume = 0
                    pkg_volume = pkg_volume - used
                    if pkg_volume < 0:
                        pkg_volume = 0
                else:
                    pkg_volume = 0
            else:
                pkg_volume = 0
                topups = float(topups) - float(used)
                if topups < 0:
                    topups = 0

        content.append({'type': 'Topups',
                        'gb': round(float(topups), 2)})
        content.append({'type': 'Used',
                        'gb': round(float(used), 2)})
        content.append({'type': 'Package',
                        'gb': round(float(pkg_volume), 2)})

        return raw_list(req, content)
