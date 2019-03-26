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

from luxon.utils.files import mkdir
from luxon.utils.pkg import Module
from luxon import register


@register.resource('system', '/setup')
def setup(req, resp):
    module = Module('calabiyau')
    mkdir("/var/tachyonic")
    mkdir("/etc/tachyonic")
    mkdir("/etc/tachyonic/freeradius")
    mkdir("/etc/tachyonic/freeradius/proxy")

    for i in range(6):
        module.copy('config/freeradius/acct%s.conf' % str(i+1),
                    '/etc/tachyonic/freeradius/acct%s.conf' % str(i+1))
        module.copy('config/freeradius/auth%s.conf' % str(i+1),
                    '/etc/tachyonic/freeradius/auth%s.conf' % str(i+1))

    module.copy('config/freeradius/clients',
                '/etc/tachyonic/freeradius/clients',
                'default')

    module.copy('config/freeradius/dictionary',
                '/etc/tachyonic/freeradius/dictionary')

    module.copy('config/freeradius/mods-config',
                '/etc/tachyonic/freeradius/mods-config')

    module.copy('config/freeradius/modules',
                '/etc/tachyonic/freeradius/modules')

    module.copy('config/freeradius/policy',
                '/etc/tachyonic/freeradius/policy')

    module.copy('config/freeradius/proxy/proxy.conf',
                '/etc/tachyonic/freeradius/proxy/proxy.conf')

    module.copy('config/freeradius/proxy/radius.conf',
                '/etc/tachyonic/freeradius/proxy/radius.conf',
                'default')

    module.copy('config/freeradius/proxy.conf',
                '/etc/tachyonic/freeradius/proxy.conf')

    module.copy('config/freeradius/python',
                '/etc/tachyonic/freeradius/python')

    module.copy('config/freeradius/servers.conf',
                '/etc/tachyonic/freeradius/servers.conf')

    module.copy('config/freeradius/sites',
                '/etc/tachyonic/freeradius/sites')

    module.copy('config/calabiyau.ini',
                '/etc/tachyonic/calabiyau.ini',
                'default')
