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

import configparser

from flask import Flask



def split_config_values(config, section_pattern):
    """
    This turns:

    [user:foo]
    key=bar
    baz=qux thud

    In to:

    {'foo': {'key': 'bar', 'baz': ['qux', 'thud']}}
    """

    return {
        section[len(section_pattern) :]: {
            key.lower(): (value.split() if " " in value else value)
            for key, value in config.items(section)
        }
        for section in config.sections()
        if section.startswith(section_pattern)
    }


def create_app(configuration=None):
    app = Flask(__name__, instance_relative_config=True)

    config = configparser.ConfigParser(interpolation=None)

    if configuration:
        config.read_string(configuration)
    else:
        config.read("proxy.ini")

    users = split_config_values(config, "user:")
    pdns = split_config_values(config, "pdns")[""]
    ldap = split_config_values(config, "ldap")[""]
    
    app.config.from_mapping(
        PDNS=pdns, USERS=users, LDAP=ldap,
    )

    from . import proxy

    app.register_blueprint(proxy.bp)

    return app
