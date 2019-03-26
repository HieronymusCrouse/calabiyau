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
from luxon import GetLogger
from luxon.utils.system import execute

log = GetLogger(__name__)


@register.resource('radius', '/start')
def start(req, resp):
    try:
        execute(['pkill', '-9', 'freeradius'])
    except Exception:
        print('Failed to kill FreeRadius')

    try:
        execute(['freeradius',
                 '-d', '/etc/tachyonic/freeradius',
                 '-n', 'proxy'])
    except Exception:
        print('Failed to start FreeRadius Proxy')

    for i in range(6):
        try:
            execute(['freeradius',
                     '-d', '/etc/tachyonic/freeradius',
                     '-n', 'auth%s' % str(i+1)])
        except Exception:
            print('Failed to start FreeRadius Auth%s' % str(i+1))

        try:
            execute(['freeradius',
                     '-d', '/etc/tachyonic/freeradius',
                     '-n', 'acct%s' % str(i+1)])
        except Exception:
            print('Failed to start FreeRadius Acct%s' % str(i+1))


@register.resource('radius', '/stop')
def stop(req, resp):
    try:
        execute(['pkill', '-9', 'freeradius'])
    except Exception:
        print('Failed to kill FreeRadius')
