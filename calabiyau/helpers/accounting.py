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

from luxon import db
from luxon.utils.sql import build_where, build_like


def get_cdr(domain=None, tenant_id=None, username=None,
            session=False, page=1, limit=10, search=None):
    start = (page - 1) * limit

    where_query = {}
    if domain:
        where_query['tradius_nas.domain'] = domain
    if tenant_id:
        where_query['tenant_id'] = tenant_id
    if username:
        where_query['tradius_accounting.username'] = username
    if session:
        where_query['tradius_accounting.acctstoptime'] = None

    where, values = build_where(**where_query)

    if search:
        where2, values2 = build_like('OR', **search)
        if where2:
            if where:
                where += " AND (" + where2 + ")"
            else:
                where = where2
            values += values2

    with db() as conn:
        query = ('SELECT DISTINCT' +
                 ' tradius_accounting.id' +
                 ' as id,' +
                 ' tradius_accounting.acctsessionid' +
                 ' as acctsessionid,' +
                 ' tradius_accounting.acctuniqueid' +
                 ' as acctuniqueid,' +
                 ' tradius_accounting.username' +
                 ' as username,' +
                 ' tradius_accounting.realm' +
                 ' as realm,' +
                 ' tradius_accounting.nasipaddress' +
                 ' as nasipaddress,' +
                 ' tradius_accounting.nasportid' +
                 ' as nasportid,' +
                 ' tradius_accounting.acctstarttime' +
                 ' as acctstarttime,' +
                 ' tradius_accounting.acctupdatetime' +
                 ' as acctupdatetime,' +
                 ' tradius_accounting.acctstoptime' +
                 ' as acctstoptime,' +
                 ' tradius_accounting.acctinterval' +
                 ' as acctinterval,' +
                 ' tradius_accounting.acctsessiontime' +
                 ' as acctsessiontime,' +
                 ' tradius_accounting.acctauthentic' +
                 ' as acctauthentic,' +
                 ' tradius_accounting.connectinfo_start' +
                 ' as connectinfo_start,' +
                 ' tradius_accounting.connectinfo_stop' +
                 ' as connectinfo_stop,' +
                 ' tradius_accounting.acctinputoctets' +
                 ' as acctinputoctets,' +
                 ' tradius_accounting.acctoutputoctets' +
                 ' as acctoutputoctets,' +
                 ' tradius_accounting.calledstationid' +
                 ' as calledstationid,' +
                 ' tradius_accounting.callingstationid' +
                 ' as callingstationid,' +
                 ' tradius_accounting.acctterminatecause' +
                 ' as acctterminatecause,' +
                 ' tradius_accounting.servicetype' +
                 ' as servicetype,' +
                 ' tradius_accounting.framedprotocol' +
                 ' as framedprotocol,' +
                 ' tradius_accounting.framedipaddress' +
                 ' as framedipaddress' +
                 ' FROM' +
                 ' tradius_accounting INNER JOIN tradius_nas ON' +
                 ' tradius_accounting.nasipaddress = tradius_nas.server' +
                 ' INNER JOIN tradius_user ON' +
                 ' tradius_nas.virtual_id = tradius_user.virtual_id' +
                 ' AND' +
                 ' tradius_accounting.username = tradius_user.username')
        if where:
            query += ' WHERE %s' % where

        query += ' LIMIT %s, %s' % (start, limit,)

        crsr = conn.execute(query, values)
        records = crsr.fetchall()

    return records
