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

#ifndef SNI_GATEWAY_ACCEPT_H
#define SNI_GATEWAY_ACCEPT_H

/*
 * --sni-gateway-server auto
 *
 * Accept-time classification for a just-accepted TCP connection, used only
 * when --sni-gateway-server auto is active (both SF_SNI_PASSTHROUGH and
 * SF_SNI_GW_HTTP are set on the same socket).  Decides, from the first
 * bytes of the still-blocking accepted fd, whether the connection looks
 * like:
 *
 *   - an sni-mode decoy ClientHello (first byte 0x16), or
 *   - an HTTP/1.1 Upgrade request from an sni-tls-http-path-upgrade or
 *     sni-http-path-upgrade client (starts with the literal bytes "GET ",
 *     the only method sni_gw_http_build_upgrade() ever emits -- both client
 *     modes produce byte-identical plaintext at this point, one via a
 *     TLS-terminating gateway, the other directly), or
 *   - neither -- plain OpenVPN, or sni-tls-forwarded plaintext OpenVPN,
 *     which are indistinguishable from each other on the wire at this
 *     point and both need no eager handling here.
 *
 * Only the HTTP case needs an eager, blocking action (the existing
 * sni_gw_http_server_accept_upgrade(), unmodified) -- the 101 response it
 * sends must reach the gateway before the event loop's first HARD_RESET,
 * confirmed necessary via live testing (a lazy/non-blocking equivalent
 * causes the gateway to return an error to the client).  The sni and
 * plain/sni-tls cases need no eager action at all: they fall through to
 * the existing lazy SF_SNI_PASSTHROUGH peek in stream_buf_added() and to
 * sni_gw_http_check_and_consume_request()'s own "not HTTP -> proceed as
 * OpenVPN" self-disable, exactly as they do outside of auto mode.
 */

#include "syshead.h"

#include <stdint.h>
#include <stdbool.h>

enum sni_gw_accept_class
{
    SNI_GW_ACCEPT_NEED_MORE = 0, /* not enough bytes peeked yet to decide */
    SNI_GW_ACCEPT_SNI,           /* 0x16: sni-mode decoy ClientHello */
    SNI_GW_ACCEPT_HTTP,          /* "GET ": sni-tls-http-path-upgrade or sni-http-path-upgrade */
    SNI_GW_ACCEPT_OTHER,         /* anything else: plain OpenVPN / sni-tls */
};

/*
 * Pure decision function: given the first peek_len bytes (0..4) already
 * peeked from a connection, return the classification.  No I/O -- safe to
 * unit test directly against hand-built byte arrays.
 */
enum sni_gw_accept_class sni_gw_accept_classify_bytes(const uint8_t *peek, int peek_len);

/*
 * Thin fd-peeking wrapper: MSG_PEEK-loop on the still-blocking accepted
 * socket sd until classification resolves to SNI, HTTP, or OTHER, or a
 * bounded number of attempts is exhausted.  Never consumes bytes -- the
 * peeked bytes remain available for whichever path (the eager
 * sni_gw_http_server_accept_upgrade(), or later non-blocking reads) really
 * consumes them.
 *
 * On success returns SNI_GW_ACCEPT_SNI / _HTTP / _OTHER and leaves *error
 * false.  On a hard I/O failure or peer-closed-before-enough-bytes, sets
 * *error = true and returns SNI_GW_ACCEPT_OTHER (callers must check *error
 * before trusting the return value, so a failure is never silently treated
 * as "plain OpenVPN, proceed normally").
 */
enum sni_gw_accept_class sni_gw_accept_classify_fd(socket_descriptor_t sd, bool *error);

#endif /* SNI_GATEWAY_ACCEPT_H */
