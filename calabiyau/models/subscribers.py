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
from luxon import SQLModel
from luxon.utils.timezone import now

from uuid import uuid4
from calabiyau.models.packages import calabiyau_package


@register.model()
class calabiyau_subscriber(SQLModel):
    id = SQLModel.Uuid(default=uuid4, internal=True)
    package_id = SQLModel.Uuid()
    domain = SQLModel.Fqdn(internal=True)
    tenant_id = SQLModel.Uuid(internal=True)
    username = SQLModel.Username(max_length=64, null=False)
    password = SQLModel.Password(max_length=150, null=True)
    email = SQLModel.Email(max_length=100)
    name = SQLModel.String(max_length=64)
    phone_mobile = SQLModel.Phone()
    phone_office = SQLModel.Phone()
    designation = SQLModel.Enum('', 'Mr', 'Mrs', 'Ms', 'Dr', 'Prof')
    static_ip4 = SQLModel.Ip4(null=True)
    ctx = SQLModel.SmallInt(null=False, default=0)
    notified = SQLModel.Boolean(null=False, default=True)
    enabled = SQLModel.Boolean(default=True)
    creation_time = SQLModel.DateTime(null=False, default=now, readonly=True)
    volume_expire = SQLModel.DateTime(null=True)
    package_expire = SQLModel.DateTime(null=True)
    volume_used_bytes = SQLModel.BigInt(null=False, signed=False, default=0)
    volume_used = SQLModel.Boolean(null=False, default=False)
    calabiyau_unique = SQLModel.UniqueIndex(username)
    calabiyau_pkg_ref = SQLModel.ForeignKey(package_id,
                                            calabiyau_package.id,
                                            on_delete='RESTRICT')
    primary_key = id
