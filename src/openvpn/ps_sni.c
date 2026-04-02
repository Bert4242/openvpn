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

#if SNI_PASSTHROUGH

#include "openssl_compat.h"
#include "socket.h"
#include "error.h"
#include "ps_sni.h"

static const unsigned char sni_passthrough_alpn_openvpn[] =
{
    7, 'o', 'p', 'e', 'n', 'v', 'p', 'n'
};

/*
 * SNI passthrough support
 * (--sni-passthrough-hostname / --sni-passthrough-server).
 *
 * Allows OpenVPN TCP connections to pass through SNI-aware TCP proxies such
 * as Traefik (passthrough mode) on any port, without any double encryption.
 *
 * SNI-aware proxies read the hostname from the first bytes of the TCP stream
 * and route the connection accordingly.  They expect those bytes to be
 * formatted as a ClientHello record (the standard carrier for SNI in TCP).
 *
 *   Client (--sni-passthrough-hostname <hostname>):
 *     Prepends a single SNI routing header — a minimal ClientHello record
 *     carrying the given hostname — before the OpenVPN protocol bytes.
 *     The proxy reads the hostname, routes the stream to the right backend,
 *     and forwards all bytes (including the header) unchanged.
 *
 *   Server (--sni-passthrough-server):
 *     Receives the routed stream, reads and discards the SNI routing header,
 *     then proceeds with the normal OpenVPN protocol.  Legacy clients that
 *     do not send the header are detected automatically and handled normally.
 *
 * No session of any kind is established by the routing header — it is
 * discarded immediately.  No encryption layer is added; OpenVPN's own
 * control-channel and data-channel security are used unchanged.
 */

static size_t
sni_passthrough_build_client_hello(uint8_t *buf, size_t bufsz, const char *sni)
{
    size_t ret = 0;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;

    if (!sni || !*sni)
    {
        return 0;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        goto cleanup;
    }

    ssl = SSL_new(ctx);
    if (!ssl)
    {
        goto cleanup;
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
    {
        goto cleanup;
    }

    SSL_set_bio(ssl, rbio, wbio);
    rbio = NULL;
    wbio = NULL;

    SSL_set_connect_state(ssl);

    if (!SSL_set_tlsext_host_name(ssl, sni))
    {
        goto cleanup;
    }

    if (SSL_set_alpn_protos(ssl, sni_passthrough_alpn_openvpn,
                            sizeof(sni_passthrough_alpn_openvpn)) != 0)
    {
        goto cleanup;
    }

    int handshake_ret = SSL_do_handshake(ssl);
    if (handshake_ret != 1)
    {
        int ssl_err = SSL_get_error(ssl, handshake_ret);

        if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
        {
            goto cleanup;
        }
    }

    BIO *wbio_peek = SSL_get_wbio(ssl);
    if (!wbio_peek)
    {
        goto cleanup;
    }
    else
    {
        size_t pending = (size_t)BIO_ctrl_pending(wbio_peek);
        if (!pending || pending > bufsz)
        {
            goto cleanup;
        }

        int n = BIO_read(wbio_peek, buf, (int)pending);
        if (n <= 0 || (size_t)n != pending)
        {
            goto cleanup;
        }

        ret = pending;
    }

cleanup:
    if (ssl)
    {
        SSL_free(ssl);
    }
    if (rbio)
    {
        BIO_free(rbio);
    }
    if (wbio)
    {
        BIO_free(wbio);
    }
    if (ctx)
    {
        SSL_CTX_free(ctx);
    }
    return ret;
}

/*
 * Client side (--sni-passthrough-hostname): send the SNI routing header,
 * then return.  The OpenVPN protocol follows immediately after.
 * The socket must be in blocking mode (before phase2_set_socket_flags).
 */
bool
sni_passthrough_send_client_hello(socket_descriptor_t sd, const char *sni)
{
    uint8_t buf[512];
    size_t len;
    ssize_t sent;

    len = sni_passthrough_build_client_hello(buf, sizeof(buf), sni);

    if (!len)
    {
        msg(M_NONFATAL,
            "--sni-passthrough-hostname: failed to build SNI routing header");
        goto error;
    }

    sent = 0;
    while (sent < (ssize_t)len)
    {
        ssize_t n = send(sd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-passthrough-hostname: send() failed");
            goto error;
        }
        sent += n;
    }

    msg(M_INFO, "--sni-passthrough-hostname: sent SNI routing header"
        " (hostname: %s)", sni);
    return true;

error:
    return false;
}

/*
 * Server side (--sni-passthrough-server): detect and consume the SNI routing
 * header prepended by --sni-passthrough-hostname clients before the OpenVPN
 * stream begins.  After the first packet sni_passthrough_state is
 * SNI_PT_DISABLED (0), so the entire function costs one always-not-taken
 * branch per fragment once the header has been handled.
 */
bool
sni_passthrough_consume_header(struct stream_buf *sb)
{
    if (sb->sni_passthrough_state == SNI_PT_PENDING && sb->buf.len >= 1)
    {
        if (BPTR(&sb->buf)[0] != 0x16)
        {
            /* client without --sni-passthrough-hostname. */
            msg(M_INFO, "--sni-passthrough-server: client without routing header)");
            sb->sni_passthrough_state = SNI_PT_DISABLED;
        }
        else
        {
            sb->sni_passthrough_state = SNI_PT_CONSUMING;
        }
    }
    if (sb->sni_passthrough_state == SNI_PT_CONSUMING)
    {
        int total;
        int remaining;
        uint8_t *src;

        /* Wait for the 5-byte TLS record envelope header. */
        if (sb->sni_passthrough_total < 0 && sb->buf.len >= 5)
        {
            const uint8_t *hdr = BPTR(&sb->buf);
            uint16_t payload = ((uint16_t)hdr[3] << 8) | hdr[4];
            sb->sni_passthrough_total = 5 + (int)payload;

            if (sb->sni_passthrough_total > sb->maxlen)
            {
                msg(M_WARN,
                    "--sni-passthrough-server: routing header too large (%d bytes)", sb->sni_passthrough_total);
                sb->error = true;
                return false;
            }
        }
        if (sb->sni_passthrough_total < 0
            || sb->buf.len < sb->sni_passthrough_total)
        {
            /* Not enough data yet; wait for more. */
            return false;
        }

        /* Full routing header received; discard it and reset the buffer so
         * normal OpenVPN stream parsing sees a clean slate. */
        total = sb->sni_passthrough_total;
        remaining = sb->buf.len - total;
        msg(M_INFO,"--sni-passthrough-server: discarded SNI routing header %d bytes", total);

        src = BPTR(&sb->buf) + total;
        sb->buf.len = 0;
        if (remaining > 0)
        {
            memmove(BPTR(&sb->buf), src, remaining);
            sb->buf.len = remaining;
        }
        sb->sni_passthrough_state = SNI_PT_DISABLED;
        /* Fall through to normal OpenVPN stream parsing. */
    }

    return true;
}

#endif /* SNI_PASSTHROUGH */
