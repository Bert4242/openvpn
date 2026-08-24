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

#ifndef SNI_GATEWAY_TLS_H
#define SNI_GATEWAY_TLS_H

/*
 * --sni-gateway sni-tls (client side only)
 *
 * In "sni-tls" mode the OpenVPN TCP client opens a *real* TLS session to a
 * TLS-terminating gateway (e.g. Traefik).  The gateway terminates that TLS
 * (it holds the certificate), decrypts, and forwards the plaintext OpenVPN
 * byte stream to the backend OpenVPN server.  The server therefore sees a
 * vanilla plaintext OpenVPN stream and needs no changes at all.
 *
 * There is NO decoy ClientHello here (that is "sni" mode).  After a genuine
 * TLS handshake to the gateway, every subsequent OpenVPN byte that the client
 * sends/receives on the TCP socket is tunnelled through the TLS session via
 * SSL_write()/SSL_read().
 *
 * This module is only compiled with a real OpenSSL backend.  LibreSSL and the
 * non-OpenSSL crypto backends are excluded (see the guard below); the option
 * validation in options.c rejects "sni-tls" mode on those builds.  It is also
 * incompatible with Linux-DCO (kernel does the socket I/O) and with the
 * Windows overlapped-I/O read path -- both are handled in options.c.
 */

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER)

#include "socket.h"
#include "buffer.h"

/* Opaque to the rest of the tree; defined in sni_gateway_tls.c. */
struct sni_gw_tls;

/*
 * Allocate a new (empty) TLS gateway wrapper.  Returns NULL on OOM.
 * The actual SSL_CTX/SSL objects are created by sni_gw_tls_client_handshake().
 */
struct sni_gw_tls *sni_gw_tls_new(void);

/*
 * Perform the blocking client-side TLS handshake directly on sd.
 *
 * Preconditions: sd is connected (through any http/socks proxy) and is still a
 * BLOCKING file descriptor (this must be called before the socket is switched
 * to non-blocking by phase2_set_socket_flags()).
 *
 * host       : SNI server name to send, and (unless no_verify) the name the
 *              peer certificate is verified against.  Required (non-NULL).
 * alpn_list  : optional ALPN protocol names to advertise (may be NULL).
 * alpn_count : number of entries in alpn_list (0 => advertise nothing).
 * ca_file    : optional CA bundle used to verify the gateway certificate.
 *              When NULL the system default trust store is used.
 * no_verify  : when true, skip certificate verification entirely (insecure).
 * signal_received / server_poll_timeout : mirror the http-proxy passthrough so
 *              that --server-poll-timeout and Ctrl-C interrupt a stuck
 *              handshake instead of hanging forever.
 *
 * Returns true on a completed, verified handshake, false on any failure
 * (a diagnostic is logged with msg(D_LINK_ERRORS, ...)).
 */
bool sni_gw_tls_client_handshake(struct sni_gw_tls *t, socket_descriptor_t sd,
                                 const char *host,
                                 const char *const *alpn_list, int alpn_count,
                                 const char *ca_file, bool no_verify,
                                 volatile int *signal_received,
                                 int server_poll_timeout);

/*
 * --sni-gateway sni-tls-http-path-upgrade: after sni_gw_tls_client_handshake() has completed (and
 * while sd is still BLOCKING), perform the HTTP/1.1 Upgrade handshake over the
 * TLS tunnel:
 *
 *   -> GET <path> HTTP/1.1 / Host: <host> / Connection: Upgrade /
 *      Upgrade: openvpn
 *   <- HTTP/1.1 101 Switching Protocols ...
 *
 * The request is written through the TLS session and the response status line
 * is read back and required to be "HTTP/1.1 101"; the remaining response
 * headers are drained through the terminating blank line.  Reads are performed
 * one plaintext byte at a time so that any OpenVPN bytes the gateway coalesced
 * into the same TLS record after the blank line are left buffered for the
 * steady-state sni_gw_tls_read() path.
 *
 * host / path : mirror --sni-gateway-host / --sni-gateway-path (path must be
 *               non-empty and start with '/').
 * token : mirrors --sni-gateway-upgrade-token (must match the server's
 *         --sni-gateway-server-upgrade-token).
 * signal_received / server_poll_timeout : as for the handshake, so the exchange
 *               is interruptible and cannot hang forever.
 *
 * Returns true on a completed 101 upgrade, false on any failure (logged).
 */
bool sni_gw_http_client_upgrade(struct sni_gw_tls *t, socket_descriptor_t sd,
                                const char *host, const char *path,
                                const char *token,
                                volatile int *signal_received,
                                int server_poll_timeout);

/*
 * Steady-state read (called from link_socket_read_tcp when a gw_tls session is
 * active).  sd is now NON-BLOCKING.  Reads whatever ciphertext is available on
 * sd, feeds it to the TLS engine, and returns decrypted plaintext in buf.
 *
 * buf is the fragment handed out by stream_buf_get_next(): plaintext is written
 * to BPTR(buf), up to BLEN(buf) bytes (the same region raw recv() fills), and
 * the byte count is returned -- buf->len itself is not modified, exactly like
 * the raw recv() path.
 *
 * Return value mirrors what a raw recv() would report to the stream_buf layer:
 *   > 0  : that many plaintext bytes were decrypted into buf.
 *   = 0  : no complete plaintext available yet (WANT_READ) -- caller treats it
 *          as "packet still incomplete".
 *   < 0  : fatal (peer closed / TLS error) -- caller resets the connection
 *          exactly like recv() <= 0 does today.
 */
ssize_t sni_gw_tls_read(struct sni_gw_tls *t, socket_descriptor_t sd,
                        struct buffer *buf);

/*
 * Steady-state write (called from the TCP write path when a gw_tls session is
 * active).  sd is NON-BLOCKING.  Encrypts the plaintext in buf via SSL_write()
 * and sends the resulting ciphertext on sd, buffering any ciphertext that
 * could not be sent because of EAGAIN.
 *
 * Returns the number of plaintext bytes accepted (== BLEN(buf) on success) or
 * -1 on a fatal TLS error.  See the implementation comment for exactly how the
 * non-blocking partial-write case is handled without corrupting the TLS stream
 * or dropping OpenVPN packets.
 */
ssize_t sni_gw_tls_write(struct sni_gw_tls *t, socket_descriptor_t sd,
                         struct buffer *buf);

/*
 * Returns true while encrypted bytes are waiting for the socket to become
 * writable.  sni_gw_tls_flush() retries those bytes without accepting any new
 * plaintext; EAGAIN is a successful (non-fatal) result and leaves them pending.
 */
bool sni_gw_tls_write_pending(const struct sni_gw_tls *t);
bool sni_gw_tls_flush(struct sni_gw_tls *t, socket_descriptor_t sd);

/*
 * Free all resources.  Safe to call with t == NULL.
 */
/*
 * Returns true when decrypted plaintext is buffered inside the tunnel waiting
 * to be served by sni_gw_tls_read().  The event loop consults this (via
 * sockets_read_residual) so it re-enters the read path without blocking on the
 * socket, which would otherwise stall packets coalesced into a single TLS
 * record after the fd has been fully drained.
 */
bool sni_gw_tls_read_pending(const struct sni_gw_tls *t);

void sni_gw_tls_free(struct sni_gw_tls *t);

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */

#endif /* SNI_GATEWAY_TLS_H */
