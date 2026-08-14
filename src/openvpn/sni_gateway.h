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
 * Shared core of the --sni-gateway feature: the mode enum and its two CLI
 * string parsers (client and server -- see below for why there are two, not
 * one).  Kept separate from the per-mode implementation files
 * (sni_gateway_passthrough.{c,h}, sni_gateway_tls.{c,h},
 * sni_gateway_http.{c,h}) since every mode -- and options.h/options.c, which
 * merely store the selected mode -- need this without needing any single
 * mode's implementation.
 *
 * SNI gateway mode, selected via
 * --sni-gateway <sni|sni-tls|sni-tls-http-path-upgrade|sni-http-path-upgrade>
 * (client) and --sni-gateway-server <sni|sni-http-path-upgrade|auto>
 * (server).  Note the client and server CLI string sets are DIFFERENT for
 * the HTTP-Upgrade mode: client-side "tls" tells you whether the CLIENT
 * wraps in TLS (sni-tls-http-path-upgrade does, sni-http-path-upgrade
 * doesn't); the server never terminates TLS in ANY mode, so no server mode
 * string ever has "-tls-" in it, and "sni-http-path-upgrade" server-side
 * means "accept the plaintext HTTP/1.1 Upgrade protocol" regardless of
 * which of the two client flavors produced it -- the server can't tell and
 * doesn't need to.  Both server-accepted client flavors map to the same
 * SNI_GW_HTTP enum value.
 *
 * SNI_GW_DROP: CLI value "sni" -- the existing SNI passthrough decoy
 *              behaviour: a fake ClientHello is sent/consumed and then
 *              discarded, no real TLS added.  Implemented in
 *              sni_gateway_passthrough.c.
 * SNI_GW_TLS: CLI value "sni-tls" -- a genuine TLS session to a
 *             TLS-terminating gateway (client-side only; the server never
 *             terminates TLS itself.  options.c intercepts "sni-tls" as a
 *             --sni-gateway-server argument directly, before it ever
 *             reaches sni_gateway_server_mode_from_string() below, giving
 *             it the same unified "no TLS on the server" error as the old
 *             "sni-tls-http-path-upgrade" server spelling -- neither
 *             string is a real server enum value).  Implemented in
 *             sni_gateway_tls.c.
 * SNI_GW_HTTP: client CLI value "sni-tls-http-path-upgrade", server CLI
 *              value "sni-http-path-upgrade" -- client-side, the "sni-tls"
 *              session plus an HTTP/1.1 Upgrade on a path, so the gateway
 *              can route by path; server-side, just "accept a plaintext
 *              HTTP/1.1 Upgrade request" (see note above -- this is the
 *              same server behavior SNI_GW_HTTP_PLAIN clients also hit).
 *              Implemented in sni_gateway_tls.c (the client-side upgrade,
 *              which needs the SSL object) and sni_gateway_http.c (the
 *              transport-independent protocol pieces, including the
 *              server-side accept and the plain client-side upgrade).
 * SNI_GW_AUTO: CLI value "auto" -- SERVER-SIDE ONLY, never valid for
 *              client --sni-gateway.  Accepts sni, sni-tls (for free, as
 *              with plain "sni"), and both SNI_GW_HTTP client flavors
 *              (sni-tls-http-path-upgrade via a TLS-terminating proxy, or
 *              sni-http-path-upgrade directly) on one process/port: the
 *              first bytes of each just-accepted connection are classified
 *              (see sni_gateway_accept.h) to decide whether to run the http
 *              mode's eager accept-time upgrade handling.
 * SNI_GW_HTTP_PLAIN: CLI value "sni-http-path-upgrade" -- CLIENT-SIDE ONLY
 *                    (the server-side string of the same spelling means
 *                    SNI_GW_HTTP instead -- see the two-parser note above).
 *                    The same HTTP/1.1 Upgrade handshake as SNI_GW_HTTP,
 *                    but over a PLAIN TCP socket with NO outer TLS wrap at
 *                    all.  Lets a client talk directly to an unmodified
 *                    --sni-gateway-server sni-http-path-upgrade/auto server
 *                    with no TLS-terminating proxy in front (or behind a
 *                    plain, non-TLS HTTP router).  Implemented entirely in
 *                    sni_gateway_http.c (sni_gw_http_client_upgrade_plain())
 *                    -- no SSL object needed, unlike SNI_GW_HTTP.
 */
enum sni_gateway_mode
{
    SNI_GW_DROP = 0,
    SNI_GW_TLS = 1,
    SNI_GW_HTTP = 2,
    SNI_GW_AUTO = 3,
    SNI_GW_HTTP_PLAIN = 4,
};

/*
 * Parse a --sni-gateway (CLIENT) mode argument.
 * Accepts exactly "sni", "sni-tls", "sni-tls-http-path-upgrade",
 * "sni-http-path-upgrade", "auto" (case-sensitive).  "auto" IS recognized
 * here (returning SNI_GW_AUTO) purely so options.c can give it a dedicated
 * "auto is server-only" error instead of a generic "unknown mode" one --
 * it is still rejected, just with a clearer message; "auto" is never a
 * valid client selection.
 * Returns the corresponding enum sni_gateway_mode value, or -1 if
 * the string does not match any known client mode.
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
sni_gateway_client_mode_from_string(const char *s)
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
    if (strcmp(s, "sni-http-path-upgrade") == 0)
    {
        return SNI_GW_HTTP_PLAIN;
    }
    if (strcmp(s, "auto") == 0)
    {
        return SNI_GW_AUTO;
    }
    return -1;
}

/*
 * Parse a --sni-gateway-server (SERVER) mode argument.
 * Accepts exactly "sni", "sni-http-path-upgrade", "auto" (case-sensitive)
 * -- the real server modes, nothing else.
 *
 * Neither "sni-tls" nor "sni-tls-http-path-upgrade" is recognized here.
 * Both are real, valid --sni-gateway (CLIENT) mode strings, so a user who
 * mistypes the client mode name into --sni-gateway-server (an easy
 * mistake: same option family, similar name)
 * needs a clear "there is no TLS on the server" error rather than a plain
 * "unknown mode" one.  options.c intercepts both directly -- before ever
 * calling this parser -- with exactly that one unified message, rather
 * than this function special-casing one of them for a nicer error while
 * the other falls through to a generic "unknown mode" one.
 *
 * Returns the corresponding enum sni_gateway_mode value, or -1 if
 * the string does not match any known server mode.
 */
static inline int
sni_gateway_server_mode_from_string(const char *s)
{
    if (!s)
    {
        return -1;
    }
    if (strcmp(s, "sni") == 0)
    {
        return SNI_GW_DROP;
    }
    if (strcmp(s, "sni-http-path-upgrade") == 0)
    {
        return SNI_GW_HTTP;
    }
    if (strcmp(s, "auto") == 0)
    {
        return SNI_GW_AUTO;
    }
    return -1;
}

#endif /* SNI_GATEWAY_H */
