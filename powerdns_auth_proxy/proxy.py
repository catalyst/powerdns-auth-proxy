from flask import Blueprint, current_app, Response, g, request, stream_with_context

from werkzeug.exceptions import Forbidden, BadRequest

from requests import Request, Session

from functools import wraps
import configparser
import hmac
import json

bp = Blueprint('proxy', __name__, url_prefix='/api')

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
            
        if authentication_method not in ('key', 'basic') or username not in current_app.config['USERS'] or not hmac.compare_digest(current_app.config['USERS'][username]['key'], password):
            return Response(
                'Access denied', 401,
                {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
            )
        g.user = current_app.config['USERS'][username]
        g.username = username
        return f(*args, **kwargs)
    return decorated_function

## Proxy helper methods

def proxy_to_backend(method, path, form=None):
    """
    Dispatch a particular request to the PowerDNS API.
    """
    s = Session()
    req = Request(method, "%s/%s" % (current_app.config['PDNS'].get('api-url', 'http://localhost:8081'), path), data=form)
    req = req.prepare()
    req.headers['X-API-Key'] = current_app.config['PDNS'].get('api-key', '')
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

@bp.route('/', methods=['GET'])
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

@bp.route('/v1/servers', methods=['GET'])
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

@bp.route('/v1/servers/localhost/config', methods=['GET'])
@authenticate
@json_response
def configuration():
    """
    GET: Retrieve a list of configuration items for the server. Currently returns empty, as we don't want to expose the global backend configuration.
    """
    return []

@bp.route('/v1/servers/localhost/statistics', methods=['GET'])
@authenticate
@json_response
def statistics():
    """
    GET: Retrieve a list of statistics about the server. Currently returns empty, as we don't want to expose the global backend statistics.
    """
    return []

@bp.route('/v1/servers/localhost/zones', methods=['GET', 'POST'])
@authenticate
@json_request
@json_response
def zone_list():
    """
    GET: Retrieve a list of zones that exist and belong to this account.
    POST: Create a new zone for this account.
    """
    if request.method == 'GET':
        try:
            zones = [zone for zone in json_or_none(proxy_to_backend('GET', 'zones')) if zone['account'] == g.username]
        except TypeError:
            zones = []
        return zones
    elif request.method == 'POST':
        requested_name = g.json.get('name', None)
        if requested_name and not any(requested_name.lower().endswith(prefix.lower()) for prefix in (g.user['allow-suffix-creation'] if isinstance(g.user['allow-suffix-creation'], list) else [g.user['allow-suffix-creation']])):
                raise Forbidden
        
        # override any keys specified in the configuration
        for key, value in {key[18:]:value for key, value in current_app.config['PDNS'].items() if key.startswith('override-creation-')}.items():
            g.json[key] = value
        
        # always override the account name with the right one for the logged in user
        g.json['account'] = g.username

        return proxy_to_backend('POST', 'zones', json.dumps(g.json))

@bp.route('/v1/servers/localhost/zones/<string:requested_zone>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
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

@bp.route('/v1/servers/localhost/zones/<string:requested_zone>/notify', methods=['PUT'])
@authenticate
@json_response
def zone_notify(requested_zone):
    """
    PUT: Queue a zone for notification to replicas.
    """
    zone = json_or_none(proxy_to_backend('GET', 'zones/%s' % requested_zone))
    if zone and zone.get('account', None) != g.username:
        raise Forbidden

    return proxy_to_backend('PUT', 'zones/%s/notify' % requested_zone, None)
