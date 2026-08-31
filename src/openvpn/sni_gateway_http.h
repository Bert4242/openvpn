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
 * --sni-gateway sni-tls-http-path-upgrade / sni-http-path-upgrade,
 * --sni-gateway-server sni-http-path-upgrade
 *
 * In "sni-tls-http-path-upgrade" mode the OpenVPN TCP client first opens a
 * genuine TLS session to a TLS-terminating gateway (exactly like "sni-tls"
 * mode -- see sni_gateway_tls.c), and then performs an HTTP/1.1 Upgrade
 * handshake over that TLS channel on a configured path. "sni-http-path-upgrade"
 * does the identical HTTP/1.1 Upgrade handshake but over a plain TCP socket,
 * no TLS at all:
 *
 *      GET <path> HTTP/1.1\r\n
 *      Host: <host>\r\n
 *      Connection: Upgrade\r\n
 *      Upgrade: <token>\r\n
 *      \r\n
 *
 * <token> defaults to "openvpn" (SNI_GW_HTTP_UPGRADE_TOKEN below) and is
 * overridable via --sni-gateway-upgrade-token (client) /
 * --sni-gateway-server-upgrade-token (server) -- the two MUST match for the
 * handshake to succeed.
 *
 * For "sni-tls-http-path-upgrade" clients, the gateway (Traefik) terminates
 * the TLS, routes by the HTTP path, and forwards the DECRYPTED, upgraded
 * stream (plaintext) to the OpenVPN backend; "sni-http-path-upgrade" clients
 * send that same plaintext stream directly, no gateway required. Either way
 * the OpenVPN server, in "sni-http-path-upgrade" server mode, consumes the
 * inbound plaintext HTTP Upgrade request the same way -- it never terminates
 * TLS itself and cannot tell (and does not need to tell) which of the two
 * client flavors it's talking to -- and replies:
 *
 *      HTTP/1.1 101 Switching Protocols\r\n
 *      Connection: Upgrade\r\n
 *      Upgrade: <token>\r\n
 *      \r\n
 *
 * and then continues as normal OpenVPN.
 *
 * This module holds the transport-independent pieces:
 *   - sni_gw_http_build_upgrade():             build the client request bytes.
 *   - sni_gw_http_client_read_101():           shared client-side response
 *                                              reader/validator (used by both
 *                                              the TLS-backed and plain
 *                                              client-side upgrades below).
 *   - sni_gw_http_check_and_consume_request(): the server-side state machine
 *                                              that detects/consumes the request.
 *   - sni_gw_http_send_101():                  emit the fixed 101 response.
 *
 * The TLS-backed client-side upgrade (--sni-gateway sni-tls-http-path-upgrade)
 * lives in sni_gateway_tls.c (sni_gw_http_client_upgrade()) because it needs
 * the SSL object.  The plain-socket client-side upgrade
 * (--sni-gateway sni-http-path-upgrade, no TLS at all) lives entirely in this
 * module (sni_gw_http_client_upgrade_plain()).
 */

#include "syshead.h"

#include "sni_gateway.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct stream_buf;

/* The compiled-in DEFAULT Upgrade protocol token, used when neither
 * --sni-gateway-upgrade-token nor --sni-gateway-server-upgrade-token is set
 * (options.c resolves the default there; downstream code always receives a
 * non-NULL, already-validated token). */
#define SNI_GW_HTTP_UPGRADE_TOKEN "openvpn"

/*
 * Build the client HTTP/1.1 Upgrade request into buf.
 *
 * host  : value of the Host: header (required, non-empty).
 * path  : request-target (required, must be non-empty and start with '/').
 * token : value of the Upgrade: header (required, non-empty -- see
 *         sni_gw_upgrade_token_is_valid() in sni_gateway.h for the full
 *         charset rule; this function only checks non-empty defensively,
 *         the real validation happens once at options-parse time).
 *
 * Returns the number of bytes written (not including a NUL terminator), or 0
 * on overflow or an invalid host/path/token.  The result is NOT NUL-terminated
 * at the returned length if bufsz is exactly the request length; callers that
 * need a C string must provide bufsz > request length.
 */
size_t sni_gw_http_build_upgrade(char *buf, size_t bufsz,
                                 const char *host, const char *path,
                                 const char *token);

/*
 * Build the server "101 Switching Protocols" response into buf, using the
 * given Upgrade token. Exposed (mirroring sni_gw_http_build_upgrade) so
 * tests can assert exact bytes for arbitrary tokens.
 *
 * Returns the number of bytes written (not including a NUL terminator), or 0
 * on overflow or an invalid token.
 */
size_t sni_gw_http_build_101(char *buf, size_t bufsz, const char *token);

/*
 * Shared bounded-wait helper used by every blocking-time call site in this
 * pair of modules: gw_plain_write_all()/gw_plain_read_byte() below, and
 * gw_handshake_flush_out()/gw_handshake_fill_in() in sni_gateway_tls.c.
 * Waits up to poll_timeout seconds for sd to become ready for read (
 * for_write == false) or write (for_write == true), the same fd_set/
 * openvpn_select()/get_signal() pattern used throughout this branch's
 * blocking-time gateway I/O.  Declared here (rather than in
 * sni_gateway_tls.h) because this header is already a shared dependency of
 * both sni_gateway_tls.c and sni_gateway_http.c, while sni_gateway_tls.h is
 * only reachable when ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER;
 * defined (non-static) in sni_gateway_http.c, which already carries the
 * socket.h/fdmisc.h/sig.h/error.h includes it needs.
 *
 * log_prefix is used verbatim to build the two possible diagnostics, so
 * each call site keeps its own existing wording:
 *     msg(D_LINK_ERRORS, "%s %s timeout", log_prefix, for_write ? "write" : "read");
 *     msg(D_LINK_ERRORS | M_ERRNO, "%s select() failed", log_prefix);
 *
 * Returns true once sd is ready.  Returns false, with a diagnostic already
 * logged, on timeout or a select() error; also returns false (silently --
 * the caller is expected to unwind without logging, matching get_signal()'s
 * existing contract) when *signal_received becomes set.
 */
bool sni_gw_wait_socket(socket_descriptor_t sd, bool for_write,
                        volatile int *signal_received, int poll_timeout,
                        const char *log_prefix);

/*
 * Client side: read a byte from whatever transport a client-side Upgrade
 * caller is using (TLS tunnel or plain socket), honoring poll_timeout and
 * signal_received the same way the two transports already do individually.
 * Returns true with *out set on success, false on timeout/signal/peer-close/
 * fatal error (the implementation is responsible for logging the specific
 * reason).
 */
typedef bool (*sni_gw_http_read_byte_fn)(void *ctx, uint8_t *out,
                                         volatile int *signal_received,
                                         int poll_timeout);

/*
 * Client side: shared "read the 101 response" loop used by both the
 * TLS-backed (sni_gateway_tls.c) and plain-socket (this module) client-side
 * Upgrade implementations.  Reads bytes one at a time via read_byte(ctx, ...)
 * until the terminating CRLF CRLF (bounded to a 1024-byte header), then
 * requires the status line to start with "HTTP/1.1 101".  log_prefix is used
 * verbatim in log messages so each transport keeps its own existing wording.
 * Returns true on a validated 101 response, false otherwise (logged).
 */
bool sni_gw_http_client_read_101(sni_gw_http_read_byte_fn read_byte, void *ctx,
                                 volatile int *signal_received, int poll_timeout,
                                 const char *log_prefix);

/*
 * Client side: --sni-gateway sni-http-path-upgrade -- perform the HTTP/1.1
 * Upgrade handshake directly over the plain, still-blocking TCP socket sd --
 * no TLS at all.  host/path mirror --sni-gateway-host/--sni-gateway-path.
 * signal_received/server_poll_timeout as for sni_gw_http_client_upgrade() in
 * sni_gateway_tls.c, so this is interruptible and cannot hang forever.
 * Returns true on a completed 101 upgrade, false on any failure (logged).
 */
bool sni_gw_http_client_upgrade_plain(socket_descriptor_t sd,
                                      const char *host, const char *path,
                                      const char *token,
                                      volatile int *signal_received,
                                      int server_poll_timeout);

/*
 * Server side: drive the state machine that detects and consumes the HTTP/1.1
 * Upgrade request prepended (over the now-plaintext link) by --sni-gateway
 * sni-tls-http-path-upgrade clients (once their gateway has terminated TLS)
 * or sent directly by --sni-gateway sni-http-path-upgrade clients, before
 * the OpenVPN stream begins.  Mirrors
 * sni_gw_passthrough_check_and_consume_header().
 *
 * require_path : when non-NULL, the request-target must match it exactly
 *                (case-sensitive); a mismatch is rejected.  NULL accepts any
 *                path (the gateway is expected to gate the path).
 * token        : the required Upgrade: header token (see
 *                sni_gw_upgrade_token_is_valid() in sni_gateway.h). The
 *                request's Upgrade: header value is parsed as a
 *                comma-separated list per RFC 7230 §6.7 and matched for an
 *                EXACT (case-insensitive) element match against token --
 *                not a substring match.
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
                                          const char *require_path,
                                          const char *token);

/*
 * Server side: send the 101 response (built via sni_gw_http_build_101() with
 * the given token) on sd.  sd may be non-blocking; the (tiny) response is
 * pushed with a short bounded retry on EAGAIN.  Returns true if the whole
 * response was sent, false on a fatal socket error / timeout / invalid token.
 */
bool sni_gw_http_send_101(socket_descriptor_t sd, const char *token);

/*
 * Server side: accept of the HTTP/1.1 Upgrade handshake.  Called once on the
 * accepted fd while it is still in blocking mode (before the main event loop
 * makes it non-blocking).  Reads until CRLF CRLF, validates the request,
 * checks the path if require_path is non-NULL, checks the Upgrade token (see
 * sni_gw_http_check_and_consume_request() above), and sends the 101 response.
 *
 * signal_received / poll_timeout : each read is gated behind a bounded
 * select() (timeout poll_timeout seconds) so a peer that opens the
 * connection and sends nothing -- or trickles bytes in slowly -- can't hang
 * this call, and with it the whole single-threaded server, forever. Mirrors
 * the signal_received/server_poll_timeout convention used by the
 * client-side upgrade calls above.
 *
 * Returns true on success, false on any error (peer closed, bad request,
 * timeout, interrupted by signal, …).
 */
bool sni_gw_http_server_accept_upgrade(socket_descriptor_t sd,
                                       const char *require_path,
                                       const char *token,
                                       volatile int *signal_received,
                                       int poll_timeout);

#endif /* SNI_GATEWAY_HTTP_H */
