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

from luxon.utils.system import execute
from luxon.utils.files import rm


def pod(nas, secret, username, session):
    tmp_file = '/tmp/pod_%s_%s_%s.txt' % (nas, username, session,)
    with open(tmp_file, 'w') as pod:
        pod.write('Acct-Session-Id = "%s"\n' % session)
        pod.write('User-Name = "%s"\n' % username)
        pod.write('NAS-IP-Address = %s\n' % nas)
    try:
        execute(['/usr/bin/env',
                 'radclient',
                 '-f',
                 tmp_file,
                 '-x',
                 '%s:3799' % nas,
                 'disconnect',
                 secret])
    except Exception:
        rm(tmp_file)
        return False
    rm(tmp_file)
    return True


def coa(nas, secret, username, session, attributes):
    tmp_file = '/tmp/coa_%s_%s_%s.txt' % (nas, username, session,)
    with open(tmp_file, 'w') as coa:
        coa.write('Acct-Session-Id = "%s"\n' % session)
        coa.write('User-Name = "%s"\n' % username)
        coa.write('NAS-IP-Address = %s\n' % nas)
        for attribute in attributes:
            coa.write('%s = "%s"\n' % (attribute[0], attribute[1],))
    try:
        execute(['/usr/bin/env',
                 'radclient',
                 '-f',
                 tmp_file,
                 '-x',
                 '%s:3799' % nas,
                 'coa',
                 secret])
    except Exception:
        rm(tmp_file)
        return False
    rm(tmp_file)
    return True
