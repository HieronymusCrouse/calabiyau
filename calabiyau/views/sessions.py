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
from luxon.utils import sql
from luxon.helpers.api import sql_list
from luxon import MBClient

from calabiyau.lib.ctx import ctx


@register.resources()
class Sessions(object):
    def __init__(self):
        # Services Users
        router.add('GET', '/v1/sessions', self.sessions,
                   tag='services:view')
        router.add('PUT', '/v1/disconnect/{session_id}', self.disconnect,
                   tag='services:admin')
        router.add('PUT', '/v1/clear/{nas_id}', self.clear,
                   tag='services:admin')

    def sessions(self, req, resp):
        def ctx_val(ctx_id):
            try:
                return {'ctx': ctx[ctx_id]}
            except IndexError:
                return {'ctx': ctx_id}

        f_session_id = sql.Field('calabiyau_session.id')
        f_session_ctx = sql.Field('calabiyau_session.ctx')
        f_session_accttype = sql.Field('calabiyau_session.accttype')
        f_session_start = sql.Field('calabiyau_session.acctstarttime')
        f_session_updated = sql.Field('calabiyau_session.acctupdated')
        f_session_unique_id = sql.Field('calabiyau_session.acctuniqueid')
        f_session_ip = sql.Field(
            'INET6_NTOA(calabiyau_session.framedipaddress)')
        f_nas_ip = sql.Field(
            'INET6_NTOA(calabiyau_session.nasipaddress)')
        f_session_username = sql.Field('calabiyau_session.username')
        f_session_user_id = sql.Field('calabiyau_session.id')

        select = sql.Select('calabiyau_session')
        select.fields = (f_session_id,
                         f_session_unique_id,
                         f_session_start,
                         f_session_updated,
                         f_session_user_id,
                         f_session_username,
                         f_session_ip,
                         f_nas_ip,
                         f_session_ctx,
                         )
        select.where = f_session_accttype != sql.Value('stop')

        return sql_list(
            req,
            select,
            search={
                'calabiyau_session.acctstarttime': 'datetime',
                'calabiyau_session.acctupdated': 'datetime',
                'calabiyau_session.user_id': str,
                'calabiyau_session.username': str,
                'calabiyau_session.acctuniqueid': str,
                'calabiyau_session.framedipaddress': 'ip',
                'calabiyau_session.nasipaddress': 'ip'},
            callbacks={'ctx': ctx_val})

    def disconnect(self, req, resp, session_id):
        with MBClient('subscriber') as mb:
            mb.send('disconnect_session', {'session_id': session_id})

    def clear(self, req, resp, nas_id):
        with MBClient('subscriber') as mb:
            mb.send('clear_nas_sessions', {'nas_id': nas_id})
