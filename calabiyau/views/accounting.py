# -*- coding: utf-8 -*-
# Copyright (c) 2019 Christiaan Frans Rademan.
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
from luxon.utils import sql

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
        user = obj(req, calabiyau_subscriber, sql_id=user_id)
        f_user_id = sql.Field('user_id')
        v_user_id = sql.Value(user['id'])

        select = sql.Select('calabiyau_topup')
        select.where = f_user_id == v_user_id
        
