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
 * --sni-gateway tls (client side only)
 *
 * In "tls" mode the OpenVPN TCP client opens a *real* TLS session to a
 * TLS-terminating gateway (e.g. Traefik).  The gateway terminates that TLS
 * (it holds the certificate), decrypts, and forwards the plaintext OpenVPN
 * byte stream to the backend OpenVPN server.  The server therefore sees a
 * vanilla plaintext OpenVPN stream and needs no changes at all.
 *
 * There is NO decoy ClientHello here (that is "drop" mode).  After a genuine
 * TLS handshake to the gateway, every subsequent OpenVPN byte that the client
 * sends/receives on the TCP socket is tunnelled through the TLS session via
 * SSL_write()/SSL_read().
 *
 * This module is only compiled with a real OpenSSL backend.  LibreSSL and the
 * non-OpenSSL crypto backends are excluded (see the guard below); the option
 * validation in options.c rejects "tls" mode on those builds.  It is also
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
 * Free all resources.  Safe to call with t == NULL.
 */
void sni_gw_tls_free(struct sni_gw_tls *t);

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */

#endif /* SNI_GATEWAY_TLS_H */
