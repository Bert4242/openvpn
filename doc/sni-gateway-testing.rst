Testing --sni-gateway (sni / sni-tls / sni-tls-http-path-upgrade)
===================================================================

This document is a quick how-to for building and exercising the three
``--sni-gateway`` modes added on the ``sni-gateway-modes`` branch. It
only covers what's needed to test the feature; see ``--help`` output
in ``options.c`` for the full option reference.

Clone + branch
---------------

::

    git clone git@github.com:Bert4242/openvpn.git
    cd openvpn
    git checkout sni-gateway-modes-2

Build
-----

``sni-tls``/``sni-tls-http-path-upgrade`` modes need OpenSSL::

    autoreconf -i
    ./configure --with-crypto-library=openssl
    make -j$(nproc)
    make -C tests/unit_tests/openvpn check   # expect 21/21

DCO does not need to be disabled at build time. It is a normal build
default; OpenVPN falls back to userspace automatically, per connection
entry, whenever ``--sni-gateway sni-tls`` or
``--sni-gateway sni-tls-http-path-upgrade`` is set on that entry (same
mechanism as ``--fragment``/``--http-proxy``/``--socks-proxy``), logging
a note when it does. DCO stays available for everything else -- plain
OpenVPN, ``--sni-gateway sni``, or no ``--sni-gateway`` at all.

``sni`` mode has no build requirement beyond a plain
``./configure && make`` if that's all you're testing.

Sample configs
---------------

All three modes are client-side (``--sni-gateway``); the server opts in
with ``--sni-gateway-server``. ``sni`` and ``sni-tls-http-path-upgrade``
need matching server config; ``sni-tls`` needs no server config at all
since Traefik terminates it.

sni -- fake ClientHello, Traefik TCP-passthrough SNI routing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway sni
    sni-gateway-host vpn.example.com

server.conf::

    proto tcp-server
    port 1194
    sni-gateway-server sni

Traefik: TCP router matching ``HostSNI(vpn.example.com)``, passthrough
(no cert needed on Traefik).

sni-tls -- real TLS to Traefik, Traefik terminates, forwards plaintext
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway sni-tls
    sni-gateway-host vpn.example.com
    # sni-gateway-ca /path/to/ca-bundle.pem   (omit for system trust store)
    # sni-gateway-no-verify                   (self-signed/testing only)

server.conf::

    proto tcp-server
    port 1194
    # no --sni-gateway-server needed -- server sees plain OpenVPN

Traefik: TCP router with ``tls: {}`` and a real cert (e.g. via ACME),
forwarding to ``openvpn-server:1194``.

sni-tls-http-path-upgrade -- like sni-tls, plus HTTP/1.1 Upgrade so Traefik can path-route
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 443 tcp
    sni-gateway sni-tls-http-path-upgrade
    sni-gateway-host vpn.example.com
    sni-gateway-path /vpn-upgrade

server.conf::

    proto tcp-server
    port 1194
    sni-gateway-server sni-tls-http-path-upgrade
    sni-gateway-server-path /vpn-upgrade

Traefik: HTTP router matching ``Host(vpn.example.com) &&
Path(/vpn-upgrade)``, ``tls: {}``, forwarding to
``http://openvpn-server:1194``.

Notes
-----

- ``--sni-gateway-alpn`` defaults to ``hacky-sni-passthrough/1`` if
  unset; it must match between client and server.
- ``sni-tls``/``sni-tls-http-path-upgrade`` require a TCP client
  (``remote ... tcp``) and are rejected at parse time on Windows.
- Success looks like ``Initialization Sequence Completed`` on the
  client; add ``-v 7`` on both ends if something stalls.
