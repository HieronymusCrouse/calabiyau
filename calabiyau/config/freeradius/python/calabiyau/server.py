#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2018-2019 Christiaan Frans Rademan, Dave Kruger.
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
import datetime

import radiusd
from calabiyau.helpers import (Db,
                               parse_fr,
                               check_password,
                               get_user,
                               require_attributes,
                               get_attributes,
                               get_ip,
                               Rmq,
                               usage,
                               has_session,
                               error_handler)

from logger import Logger

log = Logger(__name__)


def instantiate(p):
    try:
        pass
    except Exception as e:
        error_handler(e)
        return -1

    return 0


def authorize(fr):
    try:
        fr = parse_fr(fr)
        if not require_attributes('access', fr, ['User-Name',
                                                 'User-Password',
                                                 'NAS-IP-Address']):
            return radiusd.RLM_MODULE_REJECT

        with Db() as dba:
            with Db(True) as dbw:
                user = get_user(dba,
                                fr['NAS-IP-Address'],
                                fr['User-Name'])

                if user is not None:
                    if not user['enabled']:
                        log.auth('Subscriber account disabled (%s)'
                                 % user['username'])
                        return radiusd.RLM_MODULE_REJECT

                    if not check_password(fr['User-Password'],
                                          user['password']):
                        log.auth('Subscriber invalid password (%s)'
                                 % user['username'])
                        return radiusd.RLM_MODULE_REJECT

                    ctx_values = ['login',
                                  'deactivate-login']
                    ctx = ctx_values[usage(dba, user)]

                    attributes = get_attributes(dba, user, ctx)

                    if not attributes and ctx == 'deactivate-login':
                        log.auth('Subscriber Account Policy deactivate (%s)'
                                 % user['username'])
                        return radiusd.RLM_MODULE_REJECT

                    if (user['static_ip4'] or
                            not user['simultaneous']):
                        if has_session(dbw, user):
                            log.auth('Subscriber duplicate session (%s)'
                                     % user['username'])
                            return radiusd.RLM_MODULE_REJECT
                        elif user['static_ip4']:
                            attributes += [('Framed-IP-Address',
                                            user['static_ip4'])]
                    if user['pool_id']:
                        ip = get_ip(dbw, user)
                        if ip:
                            attributes += [('Framed-IP-Address',
                                           ip)]
                        else:
                            log.auth('IP Pool Empty (%s) (%s)'
                                     % (user['username'],
                                        user['pool_id'],))
                            return radiusd.RLM_MODULE_REJECT
                else:
                    log.auth('User not found (%s)' % fr['User-Name'])
                    return radiusd.RLM_MODULE_NOTFOUND

            return (radiusd.RLM_MODULE_NOTFOUND,
                    tuple(attributes),
                    (('Auth-Type', 'python'),))

    except Exception as e:
        error_handler(e)
        return radiusd.RLM_MODULE_FAIL


def authenticate(fr):
    return radiusd.RLM_MODULE_OK


def checksimul(fr):
    return radiusd.RLM_MODULE_OK


def preacct(fr):
    return radiusd.RLM_MODULE_OK


def accounting(fr):
    try:
        fr = parse_fr(fr)
        if not require_attributes('access', fr, ['User-Name',
                                                 'NAS-IP-Address']):

            return radiusd.RLM_MODULE_REJECT

        with Rmq() as mb:
            message = {
                'type': 'radius_accounting',
                'msg': {'fr': fr,
                        'datetime': str(datetime.datetime.utcnow())}
            }
            mb.distribute(**message)

        with Db() as dba:
            user = get_user(dba,
                            fr['NAS-IP-Address'],
                            fr['User-Name'])

            if user is not None:
                return (radiusd.RLM_MODULE_OK,
                        (('Tmp-String-0', user['package']),),
                        ())
            else:
                return radiusd.RLM_MODULE_OK

    except Exception as e:
        error_handler(e)
        return radiusd.RLM_MODULE_FAIL

    return radiusd.RLM_MODULE_OK


def pre_proxy(fr):
    return radiusd.RLM_MODULE_OK


def post_proxy(fr):
    return radiusd.RLM_MODULE_OK


def post_auth(fr):
    return radiusd.RLM_MODULE_OK


def recv_coa(fr):
    return radiusd.RLM_MODULE_OK


def send_coa(fr):
    return radiusd.RLM_MODULE_OK


def detach():
    Db().close()
    return radiusd.RLM_MODULE_OK
