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

#ifndef HTTPS_TUNNEL_H
#define HTTPS_TUNNEL_H

#ifdef ENABLE_CRYPTO_OPENSSL

#include <openssl/ssl.h>
#include "sig.h"

/**
 * Perform a complete HTTPS handshake on an already-connected TCP socket and
 * leave the TLS session open for subsequent use as a transport.
 *
 * After TCP connect the client performs a real TLS handshake (SSL_connect),
 * sends an HTTP/1.1 Upgrade request, and waits for the server's
 * "101 Switching Protocols" response.  All subsequent OpenVPN protocol bytes
 * are then carried inside the live TLS session via SSL_read / SSL_write.
 *
 * @param fd        Connected TCP socket descriptor.
 * @param hostname  SNI hostname for the TLS handshake and HTTP Host header.
 * @param path      HTTP request path (e.g. "/").
 * @param sig_info  Signal state; checked periodically for interruption.
 * @return          Live SSL* on success, NULL on failure (caller should
 *                  register SIGUSR1 and retry).
 */
SSL *establish_https_tunnel(int fd, const char *hostname, const char *path,
                            struct signal_info *sig_info);

/**
 * Shut down and free the outer HTTPS tunnel SSL session.
 * Sets *ssl to NULL on return.
 */
void https_tunnel_close(SSL **ssl);

/**
 * Write len bytes from buf through the outer HTTPS tunnel.
 * Returns number of bytes written, or -1 on error (errno set to EAGAIN when
 * SSL_ERROR_WANT_WRITE is returned by OpenSSL).
 */
ssize_t https_tunnel_write(SSL *ssl, const void *buf, size_t len);

/**
 * Read up to len bytes from the outer HTTPS tunnel into buf.
 * Returns number of bytes read, 0 on clean close, or -1 on error
 * (errno set to EAGAIN when SSL_ERROR_WANT_READ is returned).
 */
ssize_t https_tunnel_read(SSL *ssl, void *buf, size_t len);

#endif /* ENABLE_CRYPTO_OPENSSL */
#endif /* HTTPS_TUNNEL_H */
