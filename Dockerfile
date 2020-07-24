FROM python:3-alpine

RUN apk add --no-cache \
      supervisor \
      build-base \
      openldap-dev

COPY powerdns_auth_proxy /pdns-auth-proxy/powerdns_auth_proxy
COPY setup.py /pdns-auth-proxy/setup.py
COPY proxy.ini /pdns-auth-proxy/proxy.ini
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /pdns-auth-proxy
RUN pip install . \
    && pip install waitress

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
