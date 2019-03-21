from flask import Blueprint, current_app, Response, g, request
from flask_simpleldap import LDAP

from werkzeug.exceptions import Forbidden

from requests import Request, Session
from requests.structures import CaseInsensitiveDict

from functools import wraps
import hmac
import json

bp = Blueprint('proxy', __name__, url_prefix='/api')


def _monkey_patch_openldap_string_flask_simpleldap_1_2_0_issue_44(ldap_instance):
    import ldap

    def bind_user(self, username, password):
        user_dn = self.get_object_details(user=username, dn_only=True)

        if user_dn is None:
            return
        try:
            if type(user_dn) == bytes:
                user_dn = user_dn.decode('utf-8')

            conn = self.initialize
            conn.simple_bind_s(user_dn, password)
            return True
        except ldap.LDAPError:
            return

    import types
    ldap_instance.bind_user = types.MethodType(bind_user, ldap_instance)

    return ldap_instance


# Decorators for views
def json_request(f):
    """
    If the request contains valid JSON then store that in "g" to be used later.
    For compatibility with various things (like traefik), don't require the JSON content type.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.json = CaseInsensitiveDict(request.get_json(silent=True, force=True))
        if g.json is None:
            g.json = CaseInsensitiveDict()
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
        if isinstance(response, Response):  # pre-prepared responses get passed on whole
            return response
        if hasattr(response, 'json'):  # this is a proxied response from the backend
            status_code = response.status_code
            response = json.dumps(json_or_none(response))
        else:  # or just a regular object to serialise
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
        ldap = None

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

        elif 'X-LDAP-Auth' in request.headers:
            if not current_app.config['LDAP']['enabled']:
                return Response(
                    'LDAP not enabled for authentication', 406,
                    {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
                )
            else:
                try:
                    username, password = request.headers['X-LDAP-Auth'].split(':', 1)
                    authentication_method = 'ldap'
                except:
                    return Response(
                        'Access denied', 401,
                        {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
                    )

        elif auth:
            username = auth.username
            password = auth.password
            authentication_method = 'basic'

        if authentication_method == 'ldap':
            current_app.config['LDAP_HOST'] = current_app.config['LDAP']['host']
            current_app.config['LDAP_PORT'] = current_app.config['LDAP'].get('port', 389)
            current_app.config['LDAP_SCHEMA'] = current_app.config['LDAP'].get('protocol', 'ldap')
            current_app.config['LDAP_USE_SSL'] = current_app.config['LDAP'].get('use_ssl', False)
            current_app.config['LDAP_OPENLDAP'] = current_app.config['LDAP'].get('openldap', False)
            current_app.config['LDAP_OBJECTS_DN'] = current_app.config['LDAP'].get('objects_dn', 'distinguishedName')
            current_app.config['LDAP_BASE_DN'] = current_app.config['LDAP']['base_dn']
            current_app.config['LDAP_USERNAME'] = current_app.config['LDAP']['bind_dn']
            current_app.config['LDAP_PASSWORD'] = current_app.config['LDAP']['password']
            current_app.config['LDAP_USER_OBJECT_FILTER'] = current_app.config['LDAP']['user_object_filter']
            current_app.config['LDAP_GROUP_MEMBER_FILTER'] = current_app.config['LDAP']['group_member_filter']
            current_app.config['LDAP_GROUP_MEMBER_FILTER_FIELD'] = current_app.config['LDAP']['group_member_filter_field']

            ldap = _monkey_patch_openldap_string_flask_simpleldap_1_2_0_issue_44(LDAP(current_app))
        elif authentication_method not in ('key', 'basic')\
                or username not in current_app.config['USERS']\
                or not hmac.compare_digest(current_app.config['USERS'][username]['key'], password):
            return Response(
                'Access denied', 401,
                {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
            )

        if ldap:
            try:
                test = ldap.bind_user(username, password)

                if test is None or password == '':
                    return Response(
                        'Access denied', 401,
                        {'WWW-Authenticate': 'Basic realm="PowerDNS API"'}
                    )
                else:
                    # g.user = ldap.get_object_details(username)['pdns-allow-suffix-creation']
                    # custom value
                    g.user = {'allow-suffix-creation': "example.com."}
                    g.username = username
            except KeyError:
                pass
        else:
            g.user = current_app.config['USERS'][username]
            g.username = username
        return f(*args, **kwargs)
    return decorated_function


# Proxy helper methods
def sanitise_metadata_updates(json, config):
    """
    Ensure that the given json contains only keys that the user is allowed to update.
    """
    # override any keys specified in the configuration
    for key, value in {key[9:]: value for key, value in config.items() if key.lower().startswith('override-')}.items():
        json[key] = value

    # always override the account name with the right one for the logged in user
    json['account'] = g.username

    return json


def proxy_to_backend(method, path, form=None):
    """
    Dispatch a particular request to the PowerDNS API.
    """
    s = Session()
    req = Request(method, "%s/%s" % (current_app.config['PDNS'].get('api-url', 'http://localhost:8081'), path),
                  data=form)
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


# Proxy views
@bp.route('/', methods=['GET'])
@json_response
def api():
    """
    GET: The version returned is "1" for compability but we add an extra field to show
         that this isn't the official PowerDNS API.
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
    GET: Retrieve a list of configuration items for the server.
         Currently returns empty, as we don't want to expose the global backend configuration.
    """
    return []


@bp.route('/v1/servers/localhost/statistics', methods=['GET'])
@authenticate
@json_response
def statistics():
    """
    GET: Retrieve a list of statistics about the server.
         Currently returns empty, as we don't want to expose the global backend statistics.
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
        allowed = False
        if 'allow-suffix-creation' in g.user:
            allowed_suffixes = g.user['allow-suffix-creation'] if isinstance(g.user['allow-suffix-creation'], list)\
                else [g.user['allow-suffix-creation']]
            for suffix in allowed_suffixes:
                if suffix.startswith('.') and requested_name.lower().endswith(suffix.lower()):
                    allowed = True
                elif not suffix.startswith('.') and requested_name.lower() == suffix.lower():
                    allowed = True
        if not allowed:
            raise Forbidden

        g.json = sanitise_metadata_updates(g.json, current_app.config['PDNS'])
        return proxy_to_backend('POST', 'zones', json.dumps(dict(g.json)))


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
    if zone and len(zone) > 1 and zone.get('account', None) != g.username:
        raise Forbidden

    if request.method == 'GET':  # get metadata
        return zone
    elif request.method == 'PATCH':  # update rrsets
        return proxy_to_backend('PATCH', 'zones/%s' % requested_zone, json.dumps(dict(g.json)))
    elif request.method == 'PUT':  # update metadata
        g.json = sanitise_metadata_updates(g.json, current_app.config['PDNS'])
        return proxy_to_backend('PUT', 'zones/%s' % requested_zone, json.dumps(dict(g.json)))
    elif request.method == 'DELETE':  # delete zone
        return proxy_to_backend('DELETE', 'zones/%s' % requested_zone, json.dumps(dict(g.json)))


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
