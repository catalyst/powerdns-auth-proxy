#!/usr/bin/python3
# Copyright (c) 2017 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Authenticating proxy for PowerDNS.

Implements the PowerDNS API endpoint but with more flexible authentication.
More information about the API specification is available here: <https://doc.powerdns.com/md/httpapi/api_spec/>

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

from flask import Flask

import configparser

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    config = configparser.ConfigParser()
    config.read("proxy.ini")

    # this turns:
    #
    # [user:foo]
    # key=bar
    # baz=qux thud
    #
    # in to:
    #
    # {'foo': {'key': 'bar', 'baz': ['qux', 'thud']}}
    users = {
        section[5:] : {
            key: (value.split() if " " in value else value) 
            for key,value in config.items(section)
        } 
        for section in config.sections() 
        if section.startswith("user:")
    }

    pdns_api_key = config.get('powerdns','api-key')
    pdns_api_url = config.get('powerdns','api-url')
    
    app.config.from_mapping(
        PDNS_API_KEY=pdns_api_key,
        PDNS_API_URL=pdns_api_url,
        USERS=users,
    )
    
    if test_config is not None:
        app.config.from_mapping(test_config)

    from . import proxy
    app.register_blueprint(proxy.bp)

    return app

