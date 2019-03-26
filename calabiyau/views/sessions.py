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
from luxon.helpers.api import raw_list, search_params

from subscriber.helpers.sessions import disconnect as disc
from subscriber.helpers.sessions import clear
from subscriber.helpers.accounting import get_cdr


@register.resources()
class Accounting(object):
    def __init__(self):
        # Services Users
        router.add('GET', '/v1/sessions', self.sessions,
                   tag='services:view')
        router.add('PUT', '/v1/disconnect/{acct_id}', self.disconnect,
                   tag='services:admin')
        router.add('PUT', '/v1/clear/{nas_id}', self.clear,
                   tag='services:admin')

    def sessions(self, req, resp):
        limit = int(req.query_params.get('limit', 10))
        page = int(req.query_params.get('page', 1))

        domain = req.context_domain

        search = {}
        for field, value in search_params(req):
            search['tradius_accounting.' + field] = value

        results = get_cdr(domain=domain,
                          page=page,
                          limit=limit * 2,
                          search=search,
                          session=True)

        return raw_list(req, results, limit=limit, context=False, sql=True)

    def disconnect(self, req, resp, acct_id):
        return True 
        disc(acct_id)

    def clear(self, req, resp, nas_id):
        clear(nas_id)
