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
from luxon.helpers.api import obj, raw_list, search_params

from subscriber.helpers.accounting import get_cdr
from subscriber.models.accounting import subscriber_accounting


@register.resources()
class Accounting(object):
    def __init__(self):
        # Services Users
        router.add('GET', '/v1/accounting', self.accounting,
                   tag='services:view')
        router.add('GET', '/v1/accounting/{id}', self.cdr,
                   tag='services:view')

    def accounting(self, req, resp):
        limit = int(req.query_params.get('limit', 10))
        page = int(req.query_params.get('page', 1))

        tenant_id = req.context_tenant_id
        domain = req.context_domain

        search = {}
        for field, value in search_params(req):
            search['subscriber_accounting.' + field] = value

        results = get_cdr(tenant_id=tenant_id,
                          domain=domain,
                          page=page,
                          limit=limit * 2,
                          search=search)

        return raw_list(req, results, limit=limit, context=False, sql=True)

    def cdr(self, req, resp, id):
        return obj(req, subscriber_accounting, sql_id=id)
