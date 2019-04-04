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

from calabiyau.ui.models.subscribers import subscriber

g.nav_menu.add('/Services/Subscribers',
               href='/services/subscribers',
               tag='services:view',
               feather='users')


@register.resources()
class Subscribers():
    def __init__(self):
        router.add('GET',
                   '/services/subscribers',
                   self.list,
                   tag='services:view')

        router.add('GET',
                   '/services/subscriber/{id}',
                   self.view,
                   tag='services:view')

        router.add('GET',
                   '/services/subscriber/delete/{id}',
                   self.delete,
                   tag='services:admin')

        router.add(('GET', 'POST',),
                   '/services/subscriber/add',
                   self.add,
                   tag='services:admin')

        router.add(('GET', 'POST',),
                   '/services/subscriber/edit/{id}',
                   self.edit,
                   tag='services:admin')

    def list(self, req, resp):
        return render_template('calabiyau.ui/subscribers/list.html',
                               view='Subscribers')

    def delete(self, req, resp, id):
        req.context.api.execute('DELETE', '/v1/subscriber/%s' % id,
                                endpoint='subscriber')

    def view(self, req, resp, id):
        user = req.context.api.execute('GET', '/v1/subscriber/%s' % id,
                                       endpoint='subscriber')
        html_form = form(subscriber, user.json, readonly=True)
        return render_template('calabiyau.ui/subscribers/view.html',
                               form=html_form,
                               id=id,
                               view="View Subscriber")

    def edit(self, req, resp, id):
        if req.method == 'POST':
            data = req.form_dict
            req.context.api.execute('PUT', '/v1/subscriber/%s' % id,
                                    data=data,
                                    endpoint='subscriber')
            req.method = 'GET'
            return self.view(req, resp, id)
        else:
            user = req.context.api.execute('GET',
                                           '/v1/subscriber/%s' % id,
                                           endpoint='subscriber')
            html_form = form(subscriber, user.json)
            return render_template(
                'calabiyau.ui/subscribers/edit.html',
                username=user.json['username'],
                form=html_form,
                id=id,
                view="Edit Subscriber")

    def add(self, req, resp):
        if req.method == 'POST':
            data = req.form_dict
            response = req.context.api.execute('POST', '/v1/subscriber',
                                               data=data,
                                               endpoint='subscriber')
            return self.view(req, resp, response.json['id'])
        else:
            html_form = form(subscriber)
            return render_template('calabiyau.ui/subscribers/add.html',
                                   view='Add Subscriber',
                                   form=html_form)
