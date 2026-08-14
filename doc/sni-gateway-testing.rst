Testing --sni-gateway (sni / sni-tls / sni-tls-http-path-upgrade / sni-http-path-upgrade)
===========================================================================================

This document is a quick how-to for building and exercising the four
``--sni-gateway`` client modes, plus the server-side ``auto`` mode that
accepts all of them on one port, added on the ``sni-gateway-modes`` branch.
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

All four modes are client-side (``--sni-gateway``); the server opts in
with ``--sni-gateway-server``. ``sni``, ``sni-tls-http-path-upgrade``, and
``sni-http-path-upgrade`` need matching server config; ``sni-tls`` needs no
server config at all since Traefik terminates it. A fifth, server-only
value, ``--sni-gateway-server auto``, accepts ``sni``/``sni-tls``/
``sni-tls-http-path-upgrade``/``sni-http-path-upgrade`` client connections
on one process/port (see the ``auto`` section below) instead of needing a
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
    sni-gateway-server sni-http-path-upgrade
    sni-gateway-server-path /vpn-upgrade

Traefik: HTTP router matching ``Host(vpn.example.com) &&
Path(/vpn-upgrade)``, ``tls: {}``, forwarding to
``http://openvpn-server:1194``.

sni-http-path-upgrade -- the same Upgrade dance, no outer TLS at all
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

client.conf::

    remote gateway.example.com 1194 tcp
    sni-gateway sni-http-path-upgrade
    sni-gateway-host vpn.example.com
    sni-gateway-path /vpn-upgrade
    # no sni-gateway-ca / sni-gateway-no-verify -- there is no TLS session
    # to verify in this mode.

server.conf::

    proto tcp-server
    port 1194
    sni-gateway-server sni-http-path-upgrade
    sni-gateway-server-path /vpn-upgrade

This server.conf is **byte-for-byte identical** to the
``sni-tls-http-path-upgrade`` section's above -- ``--sni-gateway-server
sni-http-path-upgrade``/``auto`` accepts both this mode's clients and
``sni-tls-http-path-upgrade`` clients unchanged -- the server never
terminates TLS itself in *either* case, so it cannot tell, and does not
need to tell, which of the two produced the plaintext Upgrade request it
received. Note the server-side mode is spelled ``sni-http-path-upgrade``
(no "tls") even when pairing it with a ``sni-tls-http-path-upgrade``
client above -- the "tls" in the client mode name describes what the
*client* does, not the server; the server never had a "tls" spelling and
never will.

**No Traefik / no reverse proxy needed.** Unlike the other three modes,
this one needs no ``tls: {}`` block, and in fact no proxy in front at
all -- a direct client-to-backend TCP connection satisfies the protocol.
That's the point of the mode: it's the one to reach for when testing or
deploying directly against ``--sni-gateway-server
sni-http-path-upgrade``/``auto`` with nothing in between, or behind a
plain (non-TLS) HTTP router if you do want one.

**Security note -- don't confuse this with sni-tls-http-path-upgrade.**
The outer HTTP-Upgrade exchange, and the Host/Path routing metadata it
carries, travel in cleartext in this mode: there is no outer TLS at all.
The inner OpenVPN protocol's own independent tls-crypt/control-channel TLS
still fully protects actual VPN traffic, so this is a routing/metadata-
privacy tradeoff, not a VPN-security one -- but it is a real tradeoff, and
a different one than ``sni-tls-http-path-upgrade`` makes.

Note for ``auto`` mode: a ``sni-http-path-upgrade`` client's first bytes on
the wire (a bare ``GET /vpn-upgrade HTTP/1.1...`` request) are identical to
a ``sni-tls-http-path-upgrade`` client's post-TLS-termination bytes, so the
``auto`` classifier (see below) already handles both with no changes and
no extra Traefik router.

auto -- one server process/port, all client modes at once
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``sni`` and ``sni-tls`` already coexist for free on one
``--sni-gateway-server sni`` port. ``auto`` additionally classifies each
just-accepted connection's first bytes to also accept
``sni-tls-http-path-upgrade`` (and, for free, ``sni-http-path-upgrade`` --
see above) clients on that same port, so a single ``openvpn`` process/port
can sit behind all the Traefik routers instead of needing a second
port/process for the HTTP-Upgrade case.

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
  (``remote ... tcp``) and are rejected at parse time on Windows (they
  need an OpenSSL build). ``sni-http-path-upgrade`` also requires a TCP
  client, but needs **no** OpenSSL build and is **not** excluded on
  Windows -- it's plain sockets, no TLS involved.
- Success looks like ``Initialization Sequence Completed`` on the
  client; add ``-v 7`` on both ends if something stalls.
