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
from luxon import register
from luxon import router
from luxon.helpers.api import raw_list
from luxon import GetLogger

from calabiyau.lib.vendor import vendors

log = GetLogger(__name__)


@register.resources()
class Vendors(object):
    def __init__(self):
        router.add('GET', '/v1/vendors', self.vendors,
                   tag='login')

    def vendors(self, req, resp):
        nas_types = []

        for vendor in vendors:
            nas_types.append(vendor.upper())

        with db() as conn:
            result = conn.execute("SELECT nas_type FROM calabiyau_nas" +
                                  " GROUP by nas_type").fetchall()
            for row in result:
                nas_types.append(row['nas_type'])

            result = conn.execute("SELECT nas_type FROM" +
                                  " calabiyau_package_attr" +
                                  " GROUP by nas_type").fetchall()
            for row in result:
                nas_types.append(row['nas_type'])

            conn.commit()

        nas_types = list(set(nas_types))

        return raw_list(req, nas_types)
