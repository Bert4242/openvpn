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

/* Max length accepted for --sni-gateway-upgrade-token /
 * --sni-gateway-server-upgrade-token, in bytes. The genuine token is a
 * handful of bytes ("openvpn", "websocket", ...); this is just a sanity
 * cap, not a real protocol limit. */
#define SNI_GW_UPGRADE_TOKEN_MAXLEN 64

/*
 * Validate a user-supplied HTTP Upgrade token (--sni-gateway-upgrade-token /
 * --sni-gateway-server-upgrade-token) before it is ever spliced verbatim
 * into a raw "Upgrade: <token>\r\n" header line by sni_gateway_http.c (both
 * the client's request builder and the server's 101-response builder use
 * plain snprintf with no escaping). Requires the RFC 7230 §3.2.6 `token`
 * charset (visible US-ASCII, excluding delimiters) -- this one rule is
 * sufficient to rule out CR/LF/space/comma/colon header-injection bytes, so
 * no separate CR/LF blocklist is needed. Also enforces non-empty and
 * SNI_GW_UPGRADE_TOKEN_MAXLEN.
 */
static inline bool
sni_gw_upgrade_token_is_valid(const char *tok)
{
    if (!tok || !tok[0])
    {
        return false;
    }
    size_t len = 0;
    for (const char *p = tok; *p; p++, len++)
    {
        if (len >= SNI_GW_UPGRADE_TOKEN_MAXLEN)
        {
            return false;
        }
        unsigned char c = (unsigned char)*p;
        bool is_tchar =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || strchr("!#$%&'*+-.^_`|~", (int)c) != NULL;
        if (!is_tchar)
        {
            return false;
        }
    }
    return true;
}

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
 * (server).  Both fields are still typed as this one shared
 * `enum sni_gw_mode` (C enum constants aren't scoped to their
 * declaring enum, so a real client-only/server-only *type* split isn't
 * free -- not attempted here); instead every constant name carries an
 * explicit SNI_GW_CLIENT_ or SNI_GW_SERVER_ marker so it's always clear
 * at the call site which side a check is about.
 *
 * The client field (ce->sni_gw_mode) and the server field
 * (o->sni_gw_server_mode) are NEVER compared against each other
 * anywhere in the codebase -- each is only ever tested against constants
 * meant for its own side.  Because of that, SNI_GW_CLIENT_* and
 * SNI_GW_SERVER_* values are deliberately kept numerically INDEPENDENT
 * (no shared/aliased values, even where a client mode and a server mode
 * describe related behavior) -- aliasing would only invite the reader to
 * infer a relationship ("server mode X corresponds to client mode Y")
 * that isn't real and isn't relied on by any code.
 *
 * Note the client and server CLI string sets are DIFFERENT for the
 * HTTP-Upgrade mode: client-side "tls" tells you whether the CLIENT wraps
 * in TLS (sni-tls-http-path-upgrade does, sni-http-path-upgrade doesn't);
 * the server never terminates TLS in ANY mode, so no server mode string
 * ever has "-tls-" in it, and "sni-http-path-upgrade" server-side means
 * "accept the plaintext HTTP/1.1 Upgrade protocol" regardless of which of
 * the two client flavors produced it -- the server can't tell and doesn't
 * need to.  Both server-accepted client flavors map to the same
 * SNI_GW_SERVER_HTTP_UPGRADE value.
 *
 * SNI_GW_CLIENT_SNI: CLI value "sni" (client side).  SNI_GW_SERVER_SNI is
 *              the distinct server-side constant for the identically-named
 *              "sni" server mode -- the existing SNI passthrough decoy
 *              behaviour: a fake ClientHello is sent/consumed and then
 *              discarded, no real TLS added.  Implemented in
 *              sni_gateway_passthrough.c.
 * SNI_GW_CLIENT_TLS: CLI value "sni-tls" -- a genuine TLS session to a
 *             TLS-terminating gateway (client-side only; the server never
 *             terminates TLS itself.  options.c intercepts "sni-tls" as a
 *             --sni-gateway-server argument directly, before it ever
 *             reaches sni_gw_server_mode_from_string() below, giving
 *             it the same unified "no TLS on the server" error as the old
 *             "sni-tls-http-path-upgrade" server spelling -- neither
 *             string is a real server enum value).  Implemented in
 *             sni_gateway_tls.c.  No server-side counterpart exists.
 * SNI_GW_CLIENT_TLS_HTTP_UPGRADE: client CLI value
 *              "sni-tls-http-path-upgrade" -- the "sni-tls" session plus an
 *              HTTP/1.1 Upgrade on a path, so the gateway can route by
 *              path.  SNI_GW_SERVER_HTTP_UPGRADE is the distinct
 *              server-side constant for server CLI value
 *              "sni-http-path-upgrade": just "accept a plaintext HTTP/1.1
 *              Upgrade request" (see note above -- this is the same
 *              server behavior SNI_GW_CLIENT_HTTP_UPGRADE clients also
 *              hit).  Implemented in sni_gateway_tls.c (the client-side
 *              upgrade, which needs the SSL object) and
 *              sni_gateway_http.c (the transport-independent protocol
 *              pieces, including the server-side accept and the plain
 *              client-side upgrade).
 * SNI_GW_SERVER_AUTO: CLI value "auto" -- SERVER-SIDE ONLY, never valid for
 *              client --sni-gateway.  Accepts sni, sni-tls (for free, as
 *              with plain "sni"), and both HTTP-Upgrade client flavors
 *              (sni-tls-http-path-upgrade via a TLS-terminating proxy, or
 *              sni-http-path-upgrade directly) on one process/port: the
 *              first bytes of each just-accepted connection are classified
 *              (see sni_gateway_accept.h) to decide whether to run the http
 *              mode's eager accept-time upgrade handling.
 * SNI_GW_CLIENT_HTTP_UPGRADE: CLI value "sni-http-path-upgrade" --
 *                    CLIENT-SIDE ONLY (the server-side string of the same
 *                    spelling means SNI_GW_SERVER_HTTP_UPGRADE instead --
 *                    see the two-parser note above).  The same HTTP/1.1
 *                    Upgrade handshake as SNI_GW_CLIENT_TLS_HTTP_UPGRADE,
 *                    but over a PLAIN TCP socket with NO outer TLS wrap at
 *                    all.  Lets a client talk directly to an unmodified
 *                    --sni-gateway-server sni-http-path-upgrade/auto server
 *                    with no TLS-terminating proxy in front (or behind a
 *                    plain, non-TLS HTTP router).  Implemented entirely in
 *                    sni_gateway_http.c (sni_gw_http_client_upgrade_plain())
 *                    -- no SSL object needed, unlike the TLS-wrapped mode.
 */
enum sni_gw_mode
{
    /* Client-side values (ce->sni_gw_mode). */
    SNI_GW_CLIENT_SNI = 0,
    SNI_GW_CLIENT_TLS = 1,
    SNI_GW_CLIENT_TLS_HTTP_UPGRADE = 2,
    SNI_GW_CLIENT_HTTP_UPGRADE = 3,

    /* Server-side values (o->sni_gw_server_mode).  Numbered
     * independently of the client values above on purpose -- see the
     * "NEVER compared against each other" note earlier in this comment. */
    SNI_GW_SERVER_SNI = 4,
    SNI_GW_SERVER_HTTP_UPGRADE = 5,
    SNI_GW_SERVER_AUTO = 6,
};

/*
 * Parse a --sni-gateway (CLIENT) mode argument.
 * Accepts exactly "sni", "sni-tls", "sni-tls-http-path-upgrade",
 * "sni-http-path-upgrade", "auto" (case-sensitive).  "auto" IS recognized
 * here (returning SNI_GW_SERVER_AUTO) purely so options.c can give it a
 * dedicated "auto is server-only" error instead of a generic "unknown
 * mode" one -- it is still rejected, just with a clearer message; "auto"
 * is never a valid client selection.
 * Returns the corresponding enum sni_gw_mode value, or -1 if
 * the string does not match any known client mode.
 *
 * Defined as a header-only static inline (rather than in a .c file) so
 * that it does not add a new externally-linked symbol to any of the
 * per-mode implementation files: sni_gateway_passthrough.c in particular
 * is compiled a second time (with public symbols renamed via macros) by
 * tests/unit_tests/openvpn/sni_alt_impl.c, and any additional non-static,
 * non-renamed symbol pulled in there would collide at link time with the
 * ordinary sni_gw_passthrough.o in sni_compat_testdriver.
 */
static inline int
sni_gw_client_mode_from_string(const char *s)
{
    if (!s)
    {
        return -1;
    }
    if (strcmp(s, "sni") == 0)
    {
        return SNI_GW_CLIENT_SNI;
    }
    if (strcmp(s, "sni-tls") == 0)
    {
        return SNI_GW_CLIENT_TLS;
    }
    if (strcmp(s, "sni-tls-http-path-upgrade") == 0)
    {
        return SNI_GW_CLIENT_TLS_HTTP_UPGRADE;
    }
    if (strcmp(s, "sni-http-path-upgrade") == 0)
    {
        return SNI_GW_CLIENT_HTTP_UPGRADE;
    }
    if (strcmp(s, "auto") == 0)
    {
        return SNI_GW_SERVER_AUTO;
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
 * Returns the corresponding enum sni_gw_mode value, or -1 if
 * the string does not match any known server mode.
 */
static inline int
sni_gw_server_mode_from_string(const char *s)
{
    if (!s)
    {
        return -1;
    }
    if (strcmp(s, "sni") == 0)
    {
        return SNI_GW_SERVER_SNI;
    }
    if (strcmp(s, "sni-http-path-upgrade") == 0)
    {
        return SNI_GW_SERVER_HTTP_UPGRADE;
    }
    if (strcmp(s, "auto") == 0)
    {
        return SNI_GW_SERVER_AUTO;
    }
    return -1;
}

#endif /* SNI_GATEWAY_H */
