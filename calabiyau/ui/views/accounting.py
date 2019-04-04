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

from calabiyau.ui.models.accounting import accounting


g.nav_menu.add('/Infrastructure/Subscriber/Accounting',
               href='/infrastructure/calabiyau/accounting',
               tag='services:admin',
               feather='users',
               endpoint='subscriber')


@register.resources()
class Accounting():
    def __init__(self):
        router.add('GET',
                   '/infrastructure/calabiyau/accounting',
                   self.list,
                   tag='services:admin')

        router.add('GET',
                   '/infrastructure/calabiyau/accounting/{id}',
                   self.view,
                   tag='services:admin')

    def list(self, req, resp):
        return render_template('calabiyau.ui/accounting/list.html',
                               view='Subscriber Accounting')

    def view(self, req, resp, id):
        cdr = req.context.api.execute('GET', '/v1/accounting/%s' % id,
                                      endpoint='calabiyau')
        html_form = form(accounting, cdr.json, readonly=True)
        return render_template('calabiyau.ui/accounting/view.html',
                               form=html_form,
                               view="Subscriber Accounting entry")
