# powerdns-auth-proxy

This proxy implements a subset of the PowerDNS API with more flexible authentication and per-zone access control.

More information about the PowerDNS API is available at https://doc.powerdns.com/md/httpapi/api_spec/.

Future versions of this software will also support per-RRset ACLs.

## Configuration

The proxy expects to read a `proxy.ini` file which defines ACLs, for instance:

````
[pdns]
api-key = 7128ae9eb680a14390ee22a988a9d01a
api-url = http://127.0.0.1:8081/api/v1/servers/localhost
override-soa_edit_api = INCEPTION-INCREMENT
override-nameservers = ns1.example.com. ns2.example.com. ns3.example.com. ns4.example.com.
override-kind = Master

# This user will be able to create a zone called "example.org." if it doesn't already exist, and
# then modify the records in that zone only.
[user:demo-example-org]
key = dd70d1b0eccd79a0cf5d79ddf6672dce
allow-suffix-creation = example.org.
````

This specifies the API key and URL used to connect to the PowerDNS backend, as well as allowing for certain zone metadata items which will be overriden during zone creation and metadata updates. `account` is always overriden to prevent people from moving zones around between accounts they don't control. What you override will likely depend on how much access users need in your environment.

Keys should be generated using something like `dd if=/dev/urandom bs=1 count=16 | xxd -ps` to ensure they have sufficient entropy.

## Installation

We run the application with `waitress` launched by `supervisord`, though any of the standard methods for deploying Flask 1.x applications should work. We recommend using a virtual env to install the dependencies of the application.

An example `supervisord` configuration would be:

````
[program:dnsapi]
command=/opt/dnsapi/venv/bin/waitress-serve --listen=127.0.0.1:8000 --call 'powerdns_auth_proxy:create_app'
directory=/opt/dnsapi/powerdns-auth-proxy
user=dnsapi
autostart=true
autorestart=true
````

## Running tests

The tests expect to be run on a Debian or Ubuntu system using the official PowerDNS 4.1.x upstream packages. You'll need `pytest` and `pytest-flask` installed, as well as the `pdns-server` and `pdns-backend-sqlite3` OS packages.

You can then run tests by running `pytest -v` inside the source directory.

## Authenticating

Either use HTTP Basic authentication or encode your username and key in the `X-API-Key` HTTP header with a `:` character separating the parts (e.g. add an `X-API-Key: username:key` header).

## Client compatibility

This proxy has been tested with:

* Terraform [PowerDNS provider](https://www.terraform.io/docs/providers/powerdns/index.html)
* Traefik [ACME pdns plugin](https://traefik.io/)
