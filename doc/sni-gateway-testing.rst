Testing --sni-gateway (drop / tls / http)
==========================================

This document is a quick how-to for building and exercising the three
``--sni-gateway`` modes added on the ``sni-gateway-modes`` branch. It
only covers what's needed to test the feature; see ``--help`` output
in ``options.c`` for the full option reference.

Clone + branch
---------------

::

    git clone git@github.com:Bert4242/openvpn.git
    cd openvpn
    git checkout sni-gateway-modes

Build
-----

``tls``/``http`` modes need OpenSSL and DCO off (they are userspace TLS,
incompatible with kernel data-channel offload)::

    autoreconf -i
    ./configure --with-crypto-library=openssl --disable-dco
    make -j$(nproc)
    make -C tests/unit_tests/openvpn check   # expect 21/21

``drop`` mode has no such requirement -- a plain ``./configure && make``
is enough if that's all you're testing.

Sample configs
---------------

All three modes are client-side (``--sni-gateway``); the server opts in
with ``--sni-gateway-server``. ``drop`` and ``http`` need matching server
config; ``tls`` needs no server config at all since Traefik terminates it.

drop -- fake ClientHello, Traefik TCP-passthrough SNI routing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway drop
    sni-gateway-host vpn.example.com

server.conf::

    proto tcp-server
    port 1194
    sni-gateway-server drop

Traefik: TCP router matching ``HostSNI(vpn.example.com)``, passthrough
(no cert needed on Traefik).

tls -- real TLS to Traefik, Traefik terminates, forwards plaintext
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway tls
    sni-gateway-host vpn.example.com
    # sni-gateway-ca /path/to/ca-bundle.pem   (omit for system trust store)
    # sni-gateway-no-verify                   (self-signed/testing only)

server.conf::

    proto tcp-server
    port 1194
    # no --sni-gateway-server needed -- server sees plain OpenVPN

Traefik: TCP router with ``tls: {}`` and a real cert (e.g. via ACME),
forwarding to ``openvpn-server:1194``.

http -- like tls, plus HTTP/1.1 Upgrade so Traefik can path-route
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway http
    sni-gateway-host vpn.example.com
    sni-gateway-path /vpn-upgrade

server.conf::

    proto tcp-server
    port 1194
    sni-gateway-server http
    sni-gateway-server-path /vpn-upgrade

Traefik: HTTP router matching ``Host(vpn.example.com) &&
Path(/vpn-upgrade)``, ``tls: {}``, forwarding to
``http://openvpn-server:1194``.

Notes
-----

- ``--sni-gateway-alpn`` defaults to ``hacky-sni-passthrough/1`` if
  unset; it must match between client and server.
- ``tls``/``http`` require a TCP client (``remote ... tcp``) and are
  rejected at parse time on Windows.
- Success looks like ``Initialization Sequence Completed`` on the
  client; add ``-v 7`` on both ends if something stalls.
