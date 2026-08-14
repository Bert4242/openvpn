Testing --sni-gateway (sni / sni-tls / sni-tls-http-path-upgrade)
===================================================================

This document is a quick how-to for building and exercising the three
``--sni-gateway`` client modes, plus the server-side ``auto`` mode that
accepts all three on one port, added on the ``sni-gateway-modes`` branch.
It only covers what's needed to test the feature; see ``--help`` output
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
    make -C tests/unit_tests/openvpn check   # expect all tests to pass

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
since Traefik terminates it. A fourth, server-only value,
``--sni-gateway-server auto``, accepts all three client modes on one
process/port (see the ``auto`` section below) instead of needing a
dedicated server config per mode.

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

auto -- one server process/port, all three client modes at once
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``sni`` and ``sni-tls`` already coexist for free on one
``--sni-gateway-server sni`` port. ``auto`` additionally classifies each
just-accepted connection's first bytes to also accept
``sni-tls-http-path-upgrade`` clients on that same port, so a single
``openvpn`` process/port can sit behind all three Traefik routers instead
of needing a second port/process for the HTTP-Upgrade case.

server.conf::

    proto tcp-server
    port 1298
    sni-gateway-server auto
    sni-gateway-server-path /vpn-upgrade   # optional, still enforced for http clients

Traefik: three routers, all forwarding to the *same* backend
(``los.hudzia.net:1298`` in the real deployment behind
``*.test.1blu.hudzia.net``):

- TCP router matching ``HostSNI(sni.test.1blu.hudzia.net)``, passthrough
  (no cert) -- for ``--sni-gateway sni`` clients.
- TCP router matching ``HostSNI(sni-tls.test.1blu.hudzia.net)`` with
  ``tls: {}`` -- for ``--sni-gateway sni-tls`` clients.
- HTTP router matching ``Host(sni-tls-http-path-upgrade.test.1blu.hudzia.net)
  && Path(/vpn-upgrade)``, ``tls: {}`` -- for
  ``--sni-gateway sni-tls-http-path-upgrade`` clients.

Notes
-----

- ``--sni-gateway-alpn`` defaults to ``hacky-sni-passthrough/1`` if
  unset; it must match between client and server.
- ``sni-tls``/``sni-tls-http-path-upgrade`` require a TCP client
  (``remote ... tcp``) and are rejected at parse time on Windows.
- Success looks like ``Initialization Sequence Completed`` on the
  client; add ``-v 7`` on both ends if something stalls.
