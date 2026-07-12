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

#ifndef SNI_GATEWAY_HTTP_H
#define SNI_GATEWAY_HTTP_H

/*
 * --sni-gateway http / --sni-gateway-server http
 *
 * In "http" mode the OpenVPN TCP client first opens a genuine TLS session to a
 * TLS-terminating gateway (exactly like "tls" mode -- see sni_gateway_tls.c),
 * and then performs an HTTP/1.1 Upgrade handshake over that TLS channel on a
 * configured path:
 *
 *      GET <path> HTTP/1.1\r\n
 *      Host: <host>\r\n
 *      Connection: Upgrade\r\n
 *      Upgrade: openvpn\r\n
 *      \r\n
 *
 * The gateway (Traefik) terminates the TLS, routes by the HTTP path, and
 * forwards the DECRYPTED, upgraded stream (plaintext) to the OpenVPN backend.
 * The OpenVPN server, in "http" server mode, consumes that inbound plaintext
 * HTTP Upgrade request, replies:
 *
 *      HTTP/1.1 101 Switching Protocols\r\n
 *      Connection: Upgrade\r\n
 *      Upgrade: openvpn\r\n
 *      \r\n
 *
 * and then continues as normal OpenVPN.
 *
 * This module holds the transport-independent pieces:
 *   - sni_gw_http_build_upgrade():             build the client request bytes.
 *   - sni_gw_http_check_and_consume_request(): the server-side state machine
 *                                              that detects/consumes the request.
 *   - sni_gw_http_send_101():                  emit the fixed 101 response.
 *
 * The client-side upgrade over the TLS tunnel lives in sni_gateway_tls.c
 * (sni_gw_http_client_upgrade()) because it needs the SSL object.
 */

#include "syshead.h"

#include <stddef.h>
#include <stdbool.h>

struct stream_buf;

/* The Upgrade protocol token advertised/required in both directions. */
#define SNI_GW_HTTP_UPGRADE_TOKEN "openvpn"

/*
 * Build the client HTTP/1.1 Upgrade request into buf.
 *
 * host : value of the Host: header (required, non-empty).
 * path : request-target (required, must be non-empty and start with '/').
 *
 * Returns the number of bytes written (not including a NUL terminator), or 0
 * on overflow or an invalid host/path.  The result is NOT NUL-terminated at
 * the returned length if bufsz is exactly the request length; callers that
 * need a C string must provide bufsz > request length.
 */
size_t sni_gw_http_build_upgrade(char *buf, size_t bufsz,
                                 const char *host, const char *path);

/*
 * The fixed "101 Switching Protocols" response the server sends back.  Exposed
 * so tests can assert exact bytes.
 */
extern const char sni_gw_http_101_response[];
size_t sni_gw_http_101_response_len(void);

/*
 * Server side: drive the state machine that detects and consumes the HTTP/1.1
 * Upgrade request prepended (over the now-plaintext link) by --sni-gateway http
 * clients before the OpenVPN stream begins.  Mirrors
 * sni_passthrough_check_and_consume_header().
 *
 * require_path : when non-NULL, the request-target must match it exactly
 *                (case-sensitive); a mismatch is rejected.  NULL accepts any
 *                path (the gateway is expected to gate the path).
 *
 * Return value (tri-state):
 *   > 0 : a complete, well-formed request was consumed.  The consumed bytes are
 *         removed from sb->buf (any trailing OpenVPN bytes are left in place).
 *   = 0 : need more data (request not yet complete); caller waits.
 *   < 0 : stop HTTP processing.  sb->error is set when the input was a
 *         malformed / oversized / wrong-path request (reject the connection);
 *         sb->error is left false when the first bytes were plainly not an HTTP
 *         request (a raw-OpenVPN client) -- proceed as normal OpenVPN.
 */
int sni_gw_http_check_and_consume_request(struct stream_buf *sb,
                                          const char *require_path);

/*
 * Server side: send the fixed 101 response on sd.  sd may be non-blocking; the
 * (tiny) response is pushed with a short bounded retry on EAGAIN.  Returns true
 * if the whole response was sent, false on a fatal socket error / timeout.
 */
bool sni_gw_http_send_101(socket_descriptor_t sd);

#endif /* SNI_GATEWAY_HTTP_H */
