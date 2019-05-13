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

from calabiyau.lib.vendor import vendors
from calabiyau.lib.ctx import ctx
from calabiyau.ui.models.packages import package

g.nav_menu.add('/Infrastructure/Subscriber/Packages',
               href='/infrastructure/subscriber/packages',
               tag='subscriber:view',
               feather='package',
               endpoint='subscriber')


@register.resources()
class Packages():
    def __init__(self):
        router.add('GET',
                   '/infrastructure/subscriber/packages',
                   self.list,
                   tag='subscriber:view')

        router.add('GET',
                   '/infrastructure/subscriber/package/{id}',
                   self.view,
                   tag='subscriber:view')

        router.add('GET',
                   '/infrastructure/subscriber/package/delete/{id}',
                   self.delete,
                   tag='subscriber:admin')

        router.add(('GET', 'POST',),
                   '/infrastructure/subscriber/package/add',
                   self.add,
                   tag='subscriber:admin')

        router.add(('GET', 'POST',),
                   '/infrastructure/subscriber/package/edit/{id}',
                   self.edit,
                   tag='subscriber:admin')

        router.add('POST',
                   '/infrastructure/subscriber/package/add_attr/{id}',
                   self.add_attr,
                   tag='subscriber:admin')

        router.add('GET',
                   '/infrastructure/subscriber/package/rm_attr/{id}',
                   self.rm_attr,
                   tag='subscriber:admin')

    def list(self, req, resp):
        return render_template('calabiyau.ui/packages/list.html',
                               view='Subscriber Packages')

    def delete(self, req, resp, id):
        req.context.api.execute('DELETE', '/v1/package/%s' % id,
                                endpoint='subscriber')

    def view(self, req, resp, id):
        vr = req.context.api.execute('GET', '/v1/package/%s' % id,
                                     endpoint='subscriber')
        html_form = form(package, vr.json, readonly=True)
        return render_template('calabiyau.ui/packages/view.html',
                               view='View Subscriber Package',
                               form=html_form,
                               id=id)

    def edit(self, req, resp, id):
        if req.method == 'POST':
            req.context.api.execute('PUT', '/v1/package/%s' % id,
                                    data=req.form_dict,
                                    endpoint='subscriber')
            return self.view(req, resp, id)
        else:
            response = req.context.api.execute('GET', '/v1/package/%s'
                                               % id,
                                               endpoint='subscriber')
            html_form = form(package, response.json)
            return render_template('calabiyau.ui/packages/edit.html',
                                   view='Edit Subscriber Package',
                                   name=response.json['name'],
                                   form=html_form,
                                   id=id,
                                   ctx=ctx,
                                   vendors=vendors)

    def add(self, req, resp):
        if req.method == 'POST':
            response = req.context.api.execute('POST',
                                               '/v1/package',
                                               data=req.form_dict,
                                               endpoint='subscriber')
            return self.view(req, resp, response.json['id'])
        else:
            html_form = form(package)
            return render_template('calabiyau.ui/packages/add.html',
                                   view='Add Subscriber Package',
                                   form=html_form)

    def add_attr(self, req, resp, id):
        data = req.form_dict

        uri = '/v1/package/%s/attrs' % id

        req.context.api.execute('POST', uri, data=data,
                                endpoint='subscriber')

    def rm_attr(self, req, resp, id):
        uri = '/v1/package/%s/attrs' % id
        req.context.api.execute('DELETE', uri, endpoint='subscriber')
