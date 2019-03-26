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
from uuid import uuid4

from luxon import Model


class accounting(Model):
    id = Model.Uuid(default=uuid4, internal=True)
    acctsessionid = Model.String(max_length=64, null=False, default='',
                                 label='Session ID')
    acctuniqueid = Model.String(hidden=True, max_length=32, null=False,
                                default='')
    username = Model.String(max_length=64, null=False, default='')
    realm = Model.String(max_length=64, null=True, default='', hidden=True)
    nasipaddress = Model.String(max_length=15, null=False, default='',
                                label='NAS IP')
    nasportid = Model.String(max_length=15, null=True, default=None,
                             label='NAS Port ID')
    nasporttype = Model.String(max_length=32, null=True, default=None,
                               label='NAS Port Type')
    acctstarttime = Model.DateTime(label='Start Time')
    acctupdatetime = Model.DateTime(label='Update Time')
    acctstoptime = Model.DateTime(label='Stop Time')
    acctinterval = Model.Integer(null=True, default=None,
                                 label='Update Interval')
    acctsessiontime = Model.Integer(signed=False, null=True,
                                    default=None, label='Session Time')
    acctauthentic = Model.String(null=True, default=None, max_length=32,
                                 hidden=True)
    connectinfo_start = Model.String(max_length=50, null=True,
                                     default=None)
    connectinfo_stop = Model.String(max_length=50, null=True, default=None)
    acctinputoctets = Model.BigInt(null=True, default=None,
                                   label='Input Octets')
    acctoutputoctets = Model.BigInt(null=True, default=None,
                                    label='Output Octets')
    calledstationid = Model.String(max_length=50, null=False, default='',
                                   label='Called Station ID')
    callingstationid = Model.String(max_length=50, null=False, default='',
                                    label='Calling Station ID')
    acctterminatecause = Model.String(max_length=32, null=False, default='',
                                      label='Terminate Cause')
    servicetype = Model.String(max_length=32, default=None, null=True,
                               label='Service Type')
    framedprotocol = Model.String(max_length=32, default=None, null=True,
                                  label='Framed Protocol')
    framedipaddress = Model.String(max_length=15, default='', null=False,
                                   label='Framed IP')
