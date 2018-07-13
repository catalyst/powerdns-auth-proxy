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
from flask import g
from flask import request
from flask import Response
from flask import stream_with_context

from werkzeug.exceptions import Forbidden, BadRequest

from requests import Request, Session

from functools import wraps
import configparser
import hmac
import json

app = Flask(__name__)

## Read in configuration

config = configparser.ConfigParser()
config.read("proxy.ini")

# this turns:
# [user:foo]
# key=bar
# baz=qux thud
# in to:
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

## Decorators for views

def json_request(f):
    """
    If the request contains valid JSON then store that in "g" to be used later. For compatbility with various things (like traefik), don't require the JSON content type.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.json = request.get_json(silent=True, force=True)
        if g.json is None:
            g.json = {}
        return f(*args, **kwargs)
    return decorated_function

def json_response(f):
    """
    JSON serialize the object returned from the view and send it to the browser.

    Detects if the view returns a requests response object and copies its status accordingly.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if isinstance(response, Response): # pre-prepared responses get passed on whole
            return response
        if hasattr(response, 'json'): # this is a proxied response from the backend
            status_code = response.status_code
            response = json_or_none(response)
        else: # or just a regular object to serialise
            status_code = 200
            response = json.dumps(response)

        return Response(response, status=status_code, content_type='application/json')
    return decorated_function

def authenticate(f):
    """
    Authenticate all requests for this view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
       
        authentication_method = ''

        if 'X-API-Key' in request.headers:
            try:
                username, password = request.headers['X-API-Key'].split(':', 1)
                authentication_method = 'key'
            except:
                return Response(
                    'Access denied', 401,
                    {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
                )

        elif auth:
            username = auth.username
            password = auth.password
            authentication_method = 'basic'
            
        if authentication_method not in ('key', 'basic') or username not in users or not hmac.compare_digest(users[username]['key'], password):
            return Response(
                'Access denied', 401,
                {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
            )
        g.user = users[username]
        g.username = username
        return f(*args, **kwargs)
    return decorated_function

## Proxy helper methods

def proxy_to_backend(method, path, form=None):
    """
    Dispatch a particular request to the PowerDNS API.
    """
    s = Session()
    req = Request(method, "%s/%s" % (pdns_api_url, path), data=form)
    req = req.prepare()
    req.headers['X-API-Key'] = pdns_api_key
    req.headers['Content-Type'] = 'application/json'
    return s.send(req)

def json_or_none(response):
    """
    If possible, decode the JSON in a requests response object. Otherwise return None.
    """
    try:
        return response.json()
    except:
        return None

## Proxy views

@app.route('/api', methods=['GET'])
@json_response
def api():
    """
    GET: The version returned is "1" for compability but we add an extra field to show that this isn't the official PowerDNS API.
    """
    return [
        {
            "url": "/api/v1",
            "version": 1,
            "compatibility": "PowerDNS auth proxy, PowerDNS API v1"
        }
    ]

@app.route('/api/v1/servers', methods=['GET'])
@authenticate
@json_response
def server_list():
    """
    GET: Retrieve a list of servers which can be used.
    """
    return [
        {
            'zones_url': '/api/v1/servers/localhost/zones{/zone}', 
            'config_url': '/api/v1/servers/localhost/config{/config_setting}', 
            'url': '/api/v1/servers/localhost', 
            'daemon_type': 'authoritative', 
            'version': 'PowerDNS auth proxy', 
            'type': 'Server', 
            'id': 'localhost'
        }
    ]

@app.route('/api/v1/servers/localhost/zones', methods=['GET', 'POST'])
@authenticate
@json_request
@json_response
def zone_list():
    """
    GET: Retrieve a list of zones that exist and belong to this account.
    POST: Create a new zone for this account.
    """
    if request.method == 'GET':
        zones = [zone for zone in json_or_none(proxy_to_backend('GET', 'zones')) if zone['account'] == g.username]
        return zones
    elif request.method == 'POST':
        requested_name = g.json.get('name', None)
        if requested_name and not any(requested_name.lower().endswith(prefix.lower()) for prefix in g.user['allow-suffix-creation']):
                raise Forbidden
        g.json['account'] = g.username
        return proxy_to_backend('POST', 'zones', json.dumps(g.json))

@app.route('/api/v1/servers/localhost/zones/<string:requested_zone>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@authenticate
@json_request
@json_response
def zone_detail(requested_zone):
    """
    GET: Retrieve zone metadata.
    PUT: Update zone metadata.
    PATCH: Update the RRsets for a zone.
    DELETE: Delete a zone immediately.
    """
    zone = json_or_none(proxy_to_backend('GET', 'zones/%s' % requested_zone))
    if zone and zone.get('account', None) != g.username:
        raise Forbidden

    if request.method == 'GET': # get metadata
        return zone
    elif request.method == 'PATCH': # update rrsets
        return proxy_to_backend('PATCH', 'zones/%s' % requested_zone, json.dumps(g.json))
    elif request.method == 'PUT': # update metadata
        return proxy_to_backend('PUT', 'zones/%s' % requested_zone, json.dumps(g.json))
    elif request.method == 'DELETE': # delete zone
        return proxy_to_backend('DELETE', 'zones/%s' % requested_zone, json.dumps(g.json))

@app.route('/api/v1/servers/localhost/zones/<string:requested_zone>/notify', methods=['PUT'])
@authenticate
@json_response
def zone_notify(requested_zone):
    """
    PUT: Queue a zone for notification to slaves.
    """
    zone = json_or_none(proxy_to_backend('GET', 'zones/%s' % requested_zone))
    if zone and zone.get('account', None) != g.username:
        raise Forbidden

    return proxy_to_backend('PUT', 'zones/%s/notify' % requested_zone, None)

if __name__ == '__main__':
    app.run()
