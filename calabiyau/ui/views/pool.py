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
from luxon import g
from luxon import router
from luxon import register
from luxon import render_template
from luxon.utils.bootstrap4 import form

from calabiyau.ui.models.pool import pool

g.nav_menu.add('/Infrastructure/Subscriber/IP Pool',
               href='/infrastructure/subscriber/pool',
               tag='services:view',
               feather='list',
               endpoint='subscriber')


@register.resources()
class Pool():
    def __init__(self):
        router.add('GET',
                   '/infrastructure/subscriber/pool',
                   self.list,
                   tag='services')

        router.add('GET',
                   '/infrastructure/subscriber/pool/{id}',
                   self.view,
                   tag='services')

        router.add('GET',
                   '/infrastructure/subscriber/pool/delete/{id}',
                   self.delete,
                   tag='services')

        router.add(('GET', 'POST',),
                   '/infrastructure/subscriber/pool/add',
                   self.add,
                   tag='services')

        router.add(('GET', 'POST',),
                   '/infrastructure/subscriber/pool/edit/{id}',
                   self.edit,
                   tag='services')

        router.add('POST',
                   '/infrastructure/subscriber/pool/request/{id}',
                   self.request,
                   tag='services')

    def list(self, req, resp):
        return render_template('calabiyau.ui/pool/list.html',
                               view='Subscriber IP Pools')

    def delete(self, req, resp, id):
        req.context.api.execute('DELETE', '/v1/pool/%s' % id,
                                endpoint='subscriber')

    def view(self, req, resp, id):
        vr = req.context.api.execute('GET', '/v1/pool/%s' % id,
                                     endpoint='subscriber')
        html_form = form(pool, vr.json, readonly=True)
        return render_template('calabiyau.ui/pool/view.html',
                               view='Subscriber IP Pool',
                               form=html_form,
                               id=id)

    def edit(self, req, resp, id):
        if req.method == 'POST':
            req.context.api.execute('PUT', '/v1/pool/%s' % id,
                                    data=req.form_dict,
                                    endpoint='subscriber')
            return self.view(req, resp, id)
        else:
            response = req.context.api.execute('GET',
                                               '/v1/pool/%s' % id,
                                               endpoint='subscriber')
            html_form = form(pool, response.json)
            return render_template('calabiyau.ui/pool/edit.html',
                                   name=response.json['pool_name'],
                                   view='Edit Subscriber IP Pool',
                                   form=html_form,
                                   id=id)

    def add(self, req, resp):
        if req.method == 'POST':
            response = req.context.api.execute('POST', '/v1/pool',
                                               data=req.form_dict,
                                               endpoint='subscriber')
            return self.view(req, resp, response.json['id'])
        else:
            html_form = form(pool)
            return render_template('calabiyau.ui/pool/add.html',
                                   view='Add Subscriber IP Pool',
                                   form=html_form)

    def request(self, req, resp, id):
        data = {'name': req.form_dict.get('name'),
                'prefix': req.form_dict.get('prefix')}
        if req.form_dict['request'] == 'add':
            req.context.api.execute('POST', '/v1/pool/%s/add_prefix'
                                    % id,
                                    endpoint='subscriber',
                                    data=data)
        if req.form_dict['request'] == 'remove':
            req.context.api.execute('DELETE',
                                    '/v1/pool/%s/rm_prefix'
                                    % id,
                                    endpoint='subscriber',
                                    data=data)
