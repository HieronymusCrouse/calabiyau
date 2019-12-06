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
from uuid import uuid4

from luxon import register
from luxon import SQLModel

from calabiyau.models.subscribers import calabiyau_subscriber


@register.model()
class calabiyau_session(SQLModel):
    id = SQLModel.Uuid(default=uuid4, internal=True)
    user_id = SQLModel.Uuid(null=True)
    username = SQLModel.String(max_length=128, null=False, default=None)
    acctsessionid = SQLModel.String(max_length=64, null=True, default=None)
    acctuniqueid = SQLModel.String(max_length=32, null=True, default=None)
    nasipaddress = SQLModel.Ip4(null=False)
    nasportid = SQLModel.String(max_length=15, null=True, default=None)
    nasport = SQLModel.String(max_length=32, null=True, default=None)
    nasporttype = SQLModel.String(max_length=32, null=True, default=None)
    acctstarttime = SQLModel.DateTime(null=True)
    acctupdated = SQLModel.DateTime(null=True)
    processed = SQLModel.DateTime(null=True)
    calledstationid = SQLModel.String(max_length=50, null=True, default=None)
    callingstationid = SQLModel.String(max_length=50, null=True, default=None)
    servicetype = SQLModel.String(max_length=32, default=None, null=True)
    framedprotocol = SQLModel.String(max_length=32, default=None, null=True)
    framedipaddress = SQLModel.Ip4(null=True)
    acctinputoctets = SQLModel.BigInt(signed=False, null=True, default=None)
    acctoutputoctets = SQLModel.BigInt(signed=False, null=True, default=None)
    accttype = SQLModel.String(max_length=32, null=True, default='start')
    ctx = SQLModel.SmallInt(null=False, default=0)
    primary_key = id
    session_uniqueid_index = SQLModel.UniqueIndex(acctuniqueid)
    session_username_index = SQLModel.Index(user_id)
    session_ipaddress_index = SQLModel.Index(framedipaddress)
    session_acctstarttime_index = SQLModel.Index(acctstarttime)
    session_acctupdated_index = SQLModel.Index(acctupdated)
    session_acct_prune_index = SQLModel.Index(accttype, processed)
    session_nasid_index = SQLModel.Index(acctsessionid)
    session_nas_index = SQLModel.Index(nasipaddress)
