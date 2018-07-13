from contextlib import closing
import base64
import json
import os
import subprocess
import tempfile
import time

import sqlite3

import pytest

import requests

from powerdns_auth_proxy import create_app

def api_key_header(client):
    """
    Return a valid header for the X-API-Key authentication method.
    """
    user, user_data = list(client.application.config['USERS'].items())[0]
    return {'X-API-Key': "%s:%s" % (user, user_data['key'])}

def basic_auth_header(client):
    """
    Return a valid header for the Basic authentication method.
    """
    user, user_data = list(client.application.config['USERS'].items())[0]
    key = user_data['key']
    encoded = base64.b64encode(("%s:%s" % (user, key)).encode('ascii')).decode('ascii')
    return {'Authorization': "Basic %s" % (encoded, )}

@pytest.fixture
def client():
    test_config = """
    [pdns]
    api-key = 7128ae9eb680a14390ee22a988a9d01a
    api-url = http://127.0.0.1:18081/api/v1/servers/localhost
    override-creation-soa_edit_api = INCEPTION-INCREMENT
    override-creation-nameservers = ns1.example.com. ns2.example.com. ns3.example.com. ns4.example.com.
    override-creation-kind = MASTER

    [user:demo-example-org]
    key = dd70d1b0eccd79a0cf5d79ddf6672dce
    allow-suffix-creation = example.org.
    """

    pdns_db_file, pdns_db_path = tempfile.mkstemp()
    pdns_empty_dir = tempfile.TemporaryDirectory()

    pdns_config = [
        "/usr/sbin/pdns_server",
        "--config-dir=%s" % pdns_empty_dir.name,
        "--socket-dir=%s" % pdns_empty_dir.name,
        "--local-address=127.0.0.1",
        "--local-port=15353",
        "--master=yes",
        "--launch=gsqlite3",
        "--gsqlite3-database=%s" % pdns_db_path,
        "--default-soa-name=ns1.example.org",
        "--default-soa-mail=dns.example.org",
        "--webserver-port=18081",
        "--api=yes",
        "--api-key=7128ae9eb680a14390ee22a988a9d01a",
    ]

    app = create_app(test_config)
    app.config['TESTING'] = True

    # create an empty database from the supplied schema
    with closing(sqlite3.connect(pdns_db_path)) as db:
        with app.open_resource('/usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.execute("INSERT INTO domains (name, type, account) VALUES ('example.net', 'MASTER', 'nobody');") # create a domain that the demo user can't read later
        db.commit()

    pdns = subprocess.Popen(pdns_config)

    # wait for powerdns to come up, in a really ugly way
    for m in range(1, 60):
        try:
            if requests.get("http://127.0.0.1:18081/api", timeout=1, headers={'X-API-Key': '7128ae9eb680a14390ee22a988a9d01a'}).status_code == 200:
                break
        except:
            pass
        time.sleep(0.5)

    yield app.test_client()

    pdns.terminate()
    pdns.wait()
    pdns_empty_dir.cleanup()
    os.unlink(pdns_db_path)

def test_api_root(client):
    json = client.get('/api/').get_json()[0]
    assert 'version' in json
    assert 'url' in json
    assert 'compatibility' in json

def test_api_auth(client):
    routes_requiring_auth = [
        '/api/v1/servers',
        '/api/v1/servers/localhost/config',
        '/api/v1/servers/localhost/statistics',
        '/api/v1/servers/localhost/zones',
    ]

    for route in routes_requiring_auth:
        # valid user can access route
        response = client.get(route, headers=api_key_header(client))
        assert response.status_code < 400
        response = client.get(route, headers=basic_auth_header(client))
        assert response.status_code < 400

        # invalid user cannot
        response = client.get(route, headers={'X-API-Key': ':'})
        assert response.status_code > 400
        response = client.get(route, headers={'X-API-Key': '*:*'})
        assert response.status_code > 400
        response = client.get(route, headers={'X-API-Key': '*'})
        assert response.status_code > 400
        response = client.get(route, headers={'X-API-Key': ''})
        assert response.status_code > 400
        response = client.get(route, headers={'Authorization': 'Basic *'})
        assert response.status_code > 400
        response = client.get(route, headers={'Authorization': 'Basic'})
        assert response.status_code > 400
        response = client.get(route, headers={'Authorization': ''})
        assert response.status_code > 400
        
        # blank user cannot
        response = client.get(route)
        assert response.status_code > 400
        response = client.get(route)
        assert response.status_code > 400

def test_api_zone_create(client):
    # zone that the user is not allowed to create
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.com.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code > 400

    # zone belonging to another user
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.net.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code > 400

    # regular zone creation
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code < 400
    
    # zone already exists, expected to fail
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code > 400

def test_api_zone_list(client):
    # create a zone to use for testing
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code < 400

    # get list of zones in account
    response = client.get('/api/v1/servers/localhost/zones', headers=api_key_header(client))
    assert response.status_code < 400
    json = response.get_json()
    assert json is not None
    assert len(json) == 1
    assert json[0]['name'] == 'example.org.'
    assert json[0]['account'] == 'demo-example-org'

def test_api_zone_delete(client):
    # create a zone to use for testing
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code < 400

    # delete created zone
    response = client.delete('/api/v1/servers/localhost/zones/example.org.', headers=api_key_header(client))
    assert response.status_code < 400
    
    # delete a zone belonging to another user, should return exactly 403 to prevent enumeration
    response = client.delete('/api/v1/servers/localhost/zones/example.net.', headers=api_key_header(client))
    assert response.status_code == 403
    
    # delete a zone that doesn't exist, should return exactly 403 to prevent enumeration
    response = client.delete('/api/v1/servers/localhost/zones/example.com.', headers=api_key_header(client))
    assert response.status_code == 403

def test_api_zone_get(client):
    # create a zone to use for testing
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code < 400

    # retrieve zone that was created
    response = client.get('/api/v1/servers/localhost/zones/example.org.', headers=api_key_header(client))
    assert response.status_code < 400
    json = response.get_json()
    assert json['name'] == 'example.org.'
    assert json['account'] == 'demo-example-org'

    # retrieve zone that belongs to another user, should return exactly 403 to prevent enumeration
    response = client.get('/api/v1/servers/localhost/zones/example.net.', headers=api_key_header(client))
    assert response.status_code == 403
    
    # retrieve zone that doesn't exist, should return exactly 403 to prevent enumeration
    response = client.get('/api/v1/servers/localhost/zones/example.com.', headers=api_key_header(client))
    assert response.status_code == 403

def test_api_zone_create_override(client):
    # try and specify an option that is overriden
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"account": "nobody", "masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "Invalid"})
    assert response.status_code < 400
    
    # retrieve zone that was created
    response = client.get('/api/v1/servers/localhost/zones/example.org.', headers=api_key_header(client))
    assert response.status_code < 400
    json = response.get_json()
    print(json)
    assert json['name'] == 'example.org.'
    assert json['account'] == 'demo-example-org'
    assert json['soa_edit_api'] == 'INCEPTION-INCREMENT'
    
    # check that the override was properly applied to the nameserver records
    assert 'rrsets' in json
    found_ns = False
    for m in json['rrsets']:
        if m['type'] == 'NS':
            assert len(m['records']) == 4 # four override NS records
            found_ns = True
    assert found_ns is True

def test_api_zone_put(client):
    # create a zone to use for testing
    response = client.post('/api/v1/servers/localhost/zones', headers=api_key_header(client), json={"masters": [], "name": "example.org.", "nameservers": ["ns1.example.org."], "kind": "MASTER", "soa_edit_api": "INCEPTION-INCREMENT"})
    assert response.status_code < 400

    # update the zone's metadata
    json = {
        "kind": "NATIVE",
    }
    response = client.put('/api/v1/servers/localhost/zones/example.org.', headers=api_key_header(client), json=json)
    assert response.status_code < 400
