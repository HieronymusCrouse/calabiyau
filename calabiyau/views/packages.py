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
from luxon import router
from luxon.helpers.api import sql_list, obj
from luxon.utils import sql

from calabiyau.models.packages import calabiyau_package
from calabiyau.models.package_attrs import calabiyau_package_attr
from calabiyau.helpers.radius import dictionary
from calabiyau.core.utils.radius import encode

dictionary = dictionary()


@register.resources()
class Packages(object):
    def __init__(self):
        router.add('GET', '/v1/package/{id}', self.package,
                   tag='login')
        router.add('GET', '/v1/packages', self.packages,
                   tag='login')
        router.add('POST', '/v1/package', self.create,
                   tag='services')
        router.add(['PUT', 'PATCH'], '/v1/package/{id}', self.update,
                   tag='subscriber:admin')
        router.add('DELETE', '/v1/package/{id}', self.delete,
                   tag='subscriber:admin')
        router.add('GET', '/v1/package/{id}/attrs', self.attrs,
                   tag='subscriber:view')
        router.add('POST', '/v1/package/{id}/attrs', self.add_attr,
                   tag='subscriber:admin')
        router.add('DELETE', '/v1/package/{id}/attrs', self.rm_attr,
                   tag='subscriber:admin')

    def package(self, req, resp, id):
        return obj(req, calabiyau_package, sql_id=id)

    def packages(self, req, resp):
        return sql_list(req,
                        'calabiyau_package',
                        fields=('id', 'name',),
                        search={'id': str,
                                'name': str})

    def create(self, req, resp):
        package = obj(req, calabiyau_package)
        package.commit()
        return package

    def update(self, req, resp, id):
        package = obj(req, calabiyau_package, sql_id=id)
        package.commit()
        return package

    def delete(self, req, resp, id):
        package = obj(req, calabiyau_package, sql_id=id)
        package.commit()
        return package

    def attrs(self, req, resp, id):
        f_package_id = sql.Field('calabiyau_package_attr.package_id')
        w_package_id = f_package_id == sql.Value(id)
        select = sql.Select('calabiyau_package_attr')
        select.where = w_package_id
        return sql_list(req, select,
                        fields=('id',
                                'attribute',
                                'tag',
                                'value',
                                'ctx',
                                'nas_type'),
                        search={'id': str,
                                'attribute': str,
                                'value': str,
                                'ctx': str,
                                'nas_type': str})

    def add_attr(self, req, resp, id):
        attr = obj(req, calabiyau_package_attr)
        attr['package_id'] = id
        if attr['attribute'] not in dictionary.attributes:
            raise ValueError('Invalid Attribute defined')
        if (attr['tag'] and
                not dictionary[attr['attribute']].has_tag):
            raise ValueError('Attribute has no tags')
        if (not attr['tag'] and
                dictionary[attr['attribute']].has_tag):
            raise ValueError('Attribute requires tag')

        values = dictionary[attr['attribute']].user_values
        if values:
            if attr['value'] not in values:
                raise ValueError("Attribute value error" +
                                 " '%s'." % attr['attribute'] +
                                 " Possible values: %s" %
                                 ", ".join(values.keys()))
            else:
                attr['value'] = str(values[attr['value']])

        try:
            encode(dictionary[attr['attribute']].type,
                   attr['value'])
        except Exception as err:
            raise ValueError("Attribute value error '%s': %s" %
                             (attr['attribute'],
                              err,))

        attr.commit()
        return attr

    def rm_attr(self, req, resp, id):
        attr = obj(req, calabiyau_package_attr, sql_id=id)
        attr.commit()
