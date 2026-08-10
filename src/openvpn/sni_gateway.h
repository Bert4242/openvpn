/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SNI_GATEWAY_H
#define SNI_GATEWAY_H

#include "syshead.h"

/*
 * Shared core of the --sni-gateway feature: the mode enum and its CLI
 * string parser.  Kept separate from the per-mode implementation files
 * (sni_gateway_passthrough.{c,h}, sni_gateway_tls.{c,h},
 * sni_gateway_http.{c,h}) since all three modes -- and options.h/options.c,
 * which merely store the selected mode -- need this without needing any
 * single mode's implementation.
 *
 * SNI gateway mode, selected via
 * --sni-gateway <sni|sni-tls|sni-tls-http-path-upgrade> (client) and
 * --sni-gateway-server <sni|sni-tls-http-path-upgrade> (server).
 *
 * SNI_GW_DROP: CLI value "sni" -- the existing SNI passthrough decoy
 *              behaviour: a fake ClientHello is sent/consumed and then
 *              discarded, no real TLS added.  Implemented in
 *              sni_gateway_passthrough.c.
 * SNI_GW_TLS: CLI value "sni-tls" -- a genuine TLS session to a
 *             TLS-terminating gateway (client-side only; the server never
 *             terminates TLS itself).  Implemented in sni_gateway_tls.c.
 * SNI_GW_HTTP: CLI value "sni-tls-http-path-upgrade" -- the "sni-tls"
 *              session plus an HTTP/1.1 Upgrade on a path, so the gateway
 *              can route by path.  Implemented in sni_gateway_tls.c (the
 *              client-side upgrade, which needs the SSL object) and
 *              sni_gateway_http.c (the transport-independent protocol
 *              pieces).
 */
enum sni_gateway_mode
{
    SNI_GW_DROP = 0,
    SNI_GW_TLS = 1,
    SNI_GW_HTTP = 2,
};

/*
 * Parse a --sni-gateway[-server] mode argument.
 * Accepts exactly "sni", "sni-tls", "sni-tls-http-path-upgrade"
 * (case-sensitive).
 * Returns the corresponding enum sni_gateway_mode value, or -1 if
 * the string does not match any known mode.
 *
 * Defined as a header-only static inline (rather than in a .c file) so
 * that it does not add a new externally-linked symbol to any of the
 * per-mode implementation files: sni_gateway_passthrough.c in particular
 * is compiled a second time (with public symbols renamed via macros) by
 * tests/unit_tests/openvpn/sni_alt_impl.c, and any additional non-static,
 * non-renamed symbol pulled in there would collide at link time with the
 * ordinary sni_gateway_passthrough.o in sni_compat_testdriver.
 */
static inline int
sni_gateway_mode_from_string(const char *s)
{
    if (!s)
    {
        return -1;
    }
    if (strcmp(s, "sni") == 0)
    {
        return SNI_GW_DROP;
    }
    if (strcmp(s, "sni-tls") == 0)
    {
        return SNI_GW_TLS;
    }
    if (strcmp(s, "sni-tls-http-path-upgrade") == 0)
    {
        return SNI_GW_HTTP;
    }
    return -1;
}

#endif /* SNI_GATEWAY_H */
