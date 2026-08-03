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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#ifdef ENABLE_CRYPTO_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "https_tunnel.h"
#include "socket.h"
#include "error.h"
#include "sig.h"
#include "buffer.h"
#include "fdmisc.h"
#include "memdbg.h"

/* Timeout in seconds for the TLS handshake and HTTP exchange phases. */
#define HTTPS_TUNNEL_TIMEOUT_SEC 60

/* ALPN wire encoding: length-prefixed string "http/1.1". */
static const unsigned char https_tunnel_alpn[] = {
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

/* User-Agent sent in the HTTP upgrade request to blend with browser traffic. */
#define HTTPS_TUNNEL_USER_AGENT                  \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    "AppleWebKit/537.36 (KHTML, like Gecko) "    \
    "Chrome/124.0.0.0 Safari/537.36"

/*
 * Wait on fd for readability or writability with a timeout.
 * Returns >0 if ready, 0 on timeout, <0 on error.
 */
static int
https_select(int fd, bool want_write, int timeout_sec, volatile int *signal_received)
{
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    fd_set fds;
    FD_ZERO(&fds);
    openvpn_fd_set(fd, &fds);

    int status;
    if (want_write)
    {
        status = openvpn_select(fd + 1, NULL, &fds, NULL, &tv);
    }
    else
    {
        status = openvpn_select(fd + 1, &fds, NULL, NULL, &tv);
    }

    get_signal(signal_received);
    if (*signal_received)
    {
        return -1;
    }

    if (status == 0)
    {
        msg(D_LINK_ERRORS, "https_tunnel: timeout waiting for %s",
            want_write ? "write-ready" : "read-ready");
    }
    else if (status < 0)
    {
        msg(D_LINK_ERRORS | M_ERRNO, "https_tunnel: select() failed");
    }

    return status;
}

/*
 * Run SSL_connect() to completion on a non-blocking socket.
 * Returns true on success.
 */
static bool
https_tunnel_do_handshake(SSL *ssl, int fd, struct signal_info *sig_info)
{
    while (true)
    {
        int ret = SSL_connect(ssl);
        if (ret == 1)
        {
            return true;
        }

        int err = SSL_get_error(ssl, ret);
        bool want_write = (err == SSL_ERROR_WANT_WRITE);

        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            char errbuf[256];
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            msg(D_LINK_ERRORS, "https_tunnel: SSL_connect() failed: %s", errbuf);
            return false;
        }

        if (https_select(fd, want_write, HTTPS_TUNNEL_TIMEOUT_SEC,
                         &sig_info->signal_received)
            <= 0)
        {
            return false;
        }
    }
}

/*
 * Read a single byte from the TLS session with a timeout.
 * Returns true on success.
 */
static bool
ssl_recv_char(SSL *ssl, int fd, uint8_t *c, volatile int *signal_received)
{
    while (true)
    {
        int n = SSL_read(ssl, c, 1);
        if (n == 1)
        {
            return true;
        }

        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
        {
            msg(D_LINK_ERRORS, "https_tunnel: connection closed during HTTP read");
            return false;
        }
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            msg(D_LINK_ERRORS, "https_tunnel: SSL_read() error %d", err);
            return false;
        }

        bool want_write = (err == SSL_ERROR_WANT_WRITE);
        if (https_select(fd, want_write, HTTPS_TUNNEL_TIMEOUT_SEC, signal_received) <= 0)
        {
            return false;
        }
    }
}

/*
 * Read a CRLF-terminated HTTP response line from the TLS session.
 * The trailing "\r\n" is stripped; buf is NUL-terminated.
 * Returns true on success.
 */
static bool
ssl_recv_line(SSL *ssl, int fd, char *buf, size_t len, volatile int *signal_received)
{
    size_t pos = 0;
    int lastc = 0;

    while (true)
    {
        uint8_t c;
        if (!ssl_recv_char(ssl, fd, &c, signal_received))
        {
            return false;
        }

        if (pos < len - 1)
        {
            buf[pos++] = (char)c;
        }

        if (lastc == '\r' && c == '\n')
        {
            /* strip the \r\n */
            if (pos >= 2)
            {
                pos -= 2;
            }
            break;
        }
        lastc = c;
    }

    buf[pos] = '\0';
    return true;
}

/*
 * Write all bytes in buf through the TLS session.
 * Returns true on success.
 */
static bool
ssl_send_all(SSL *ssl, int fd, const void *buf, size_t len, volatile int *signal_received)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0)
    {
        int n = SSL_write(ssl, p, (int)remaining);
        if (n > 0)
        {
            p += n;
            remaining -= (size_t)n;
            continue;
        }

        int err = SSL_get_error(ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            msg(D_LINK_ERRORS, "https_tunnel: SSL_write() error %d", err);
            return false;
        }

        bool want_write = (err == SSL_ERROR_WANT_WRITE);
        if (https_select(fd, want_write, HTTPS_TUNNEL_TIMEOUT_SEC, signal_received) <= 0)
        {
            return false;
        }
    }

    return true;
}

static bool
ssl_send_line_crlf(SSL *ssl, int fd, const char *line, volatile int *signal_received)
{
    struct buffer buf = alloc_buf(strlen(line) + 2);
    ASSERT(buf_write(&buf, line, strlen(line)));
    ASSERT(buf_write(&buf, "\r\n", 2));
    bool ok = ssl_send_all(ssl, fd, BSTR(&buf), BLEN(&buf), signal_received);
    free_buf(&buf);
    return ok;
}

/*
 * Send the HTTP/1.1 upgrade request and consume the server's response.
 * Returns true if the server replied with 101 Switching Protocols.
 */
static bool
https_tunnel_http_upgrade(SSL *ssl, int fd, const char *hostname, const char *path,
                          volatile int *signal_received)
{
    /* Build and send the request. */
    struct buffer req = alloc_buf(512);

    buf_printf(&req, "GET %s HTTP/1.1", path);
    if (!ssl_send_line_crlf(ssl, fd, BSTR(&req), signal_received))
    {
        free_buf(&req);
        return false;
    }
    free_buf(&req);

    char line[256];
    snprintf(line, sizeof(line), "Host: %s", hostname);
    if (!ssl_send_line_crlf(ssl, fd, line, signal_received)
        || !ssl_send_line_crlf(ssl, fd, "Connection: Upgrade", signal_received)
        || !ssl_send_line_crlf(ssl, fd, "Upgrade: openvpn", signal_received)
        || !ssl_send_line_crlf(ssl, fd, "User-Agent: " HTTPS_TUNNEL_USER_AGENT,
                               signal_received)
        || !ssl_send_line_crlf(ssl, fd, "", signal_received)) /* blank line */
    {
        return false;
    }

    /* Read and check the status line. */
    char status[256];
    if (!ssl_recv_line(ssl, fd, status, sizeof(status), signal_received))
    {
        return false;
    }

    msg(D_PROXY, "HTTPS-TUNNEL: server response: %s", status);

    if (strncmp(status, "HTTP/1.1 101", 12) != 0)
    {
        msg(D_LINK_ERRORS, "https_tunnel: expected '101 Switching Protocols', got: %s", status);
        return false;
    }

    /* Drain remaining response headers (up to blank line). */
    while (true)
    {
        if (!ssl_recv_line(ssl, fd, status, sizeof(status), signal_received))
        {
            return false;
        }
        if (status[0] == '\0')
        {
            break; /* blank line marks end of headers */
        }
    }

    return true;
}

SSL *
establish_https_tunnel(int fd, const char *hostname, const char *path,
                       struct signal_info *sig_info)
{
    volatile int *signal_received = &sig_info->signal_received;

    msg(M_INFO, "HTTPS-TUNNEL: connecting via %s%s", hostname, path);

    /* Build a standard HTTPS client SSL context. */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        msg(D_LINK_ERRORS, "https_tunnel: SSL_CTX_new() failed");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        msg(D_TLS_ERRORS | M_ERRNO, "https_tunnel: SSL_CTX_set_default_verify_paths() failed");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Advertise http/1.1 so the connection looks like ordinary HTTPS. */
    if (SSL_CTX_set_alpn_protos(ctx, https_tunnel_alpn, sizeof(https_tunnel_alpn)) != 0)
    {
        msg(D_TLS_ERRORS, "https_tunnel: SSL_CTX_set_alpn_protos() failed");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx); /* ssl holds a reference; ctx can be freed now */
    if (!ssl)
    {
        msg(D_LINK_ERRORS, "https_tunnel: SSL_new() failed");
        return NULL;
    }

    /* Attach the (non-blocking) socket to the SSL object. */
    if (!SSL_set_fd(ssl, fd))
    {
        msg(D_LINK_ERRORS, "https_tunnel: SSL_set_fd() failed");
        SSL_free(ssl);
        return NULL;
    }

    /* Set SNI so the server presents the right certificate. */
    if (!SSL_set_tlsext_host_name(ssl, hostname))
    {
        msg(D_TLS_ERRORS, "https_tunnel: SSL_set_tlsext_host_name() failed");
        SSL_free(ssl);
        return NULL;
    }

    /* Set expected hostname for certificate verification. */
    if (!SSL_set1_host(ssl, hostname))
    {
        msg(D_TLS_ERRORS, "https_tunnel: SSL_set1_host() failed");
        SSL_free(ssl);
        return NULL;
    }

    /* Run the TLS handshake. */
    if (!https_tunnel_do_handshake(ssl, fd, sig_info))
    {
        SSL_free(ssl);
        return NULL;
    }

    msg(D_TLS_DEBUG, "HTTPS-TUNNEL: TLS handshake complete");

    /* Send the HTTP upgrade request and wait for 101. */
    if (!https_tunnel_http_upgrade(ssl, fd, hostname, path, signal_received))
    {
        register_signal(sig_info, SIGUSR1, "https-tunnel-http-error");
        SSL_free(ssl);
        return NULL;
    }

    msg(M_INFO, "HTTPS-TUNNEL: HTTP upgrade complete, tunnel active");
    return ssl;
}

void
https_tunnel_close(SSL **ssl)
{
    if (ssl && *ssl)
    {
        SSL_shutdown(*ssl);
        SSL_free(*ssl);
        *ssl = NULL;
    }
}

ssize_t
https_tunnel_write(SSL *ssl, const void *buf, size_t len)
{
    int n = SSL_write(ssl, buf, (int)len);
    if (n > 0)
    {
        return (ssize_t)n;
    }

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
    {
        errno = EAGAIN;
    }
    else
    {
        errno = EIO;
    }
    return -1;
}

ssize_t
https_tunnel_read(SSL *ssl, void *buf, size_t len)
{
    int n = SSL_read(ssl, buf, (int)len);
    if (n > 0)
    {
        return (ssize_t)n;
    }

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN)
    {
        return 0; /* clean TLS close */
    }
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        errno = EAGAIN;
    }
    else
    {
        errno = EIO;
    }
    return -1;
}

#endif /* ENABLE_CRYPTO_OPENSSL */
