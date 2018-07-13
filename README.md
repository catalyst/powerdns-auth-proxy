# powerdns-auth-proxy

This proxy implements a subset of the PowerDNS API with more flexible authentication and per-zone access control.

More information about the PowerDNS API is available at https://doc.powerdns.com/md/httpapi/api_spec/.

Future versions of this software will also support per-RRset ACLs.

## Authenticating

Either use HTTP Basic authentication or encode your username and password in the `X-API-Key` HTTP header with a `:` character separating the parts (e.g. add an `X-API-Key: username:password` header)

## Client compatibility

This proxy has been tested with:

* Terraform [PowerDNS provider](https://www.terraform.io/docs/providers/powerdns/index.html)
* Traefik [ACME pdns plugin](https://traefik.io/)
