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



            msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 1");

    if (!sni || !*sni)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 2");

        return 0;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 3");

        goto cleanup;
    }

    ssl = SSL_new(ctx);
    if (!ssl)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 4");

        goto cleanup;
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 5");

        goto cleanup;
    }

    SSL_set_bio(ssl, rbio, wbio);
    rbio = NULL;
    wbio = NULL;

    SSL_set_connect_state(ssl);

    if (!SSL_set_tlsext_host_name(ssl, sni))
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 6");

        goto cleanup;
    }

    if (SSL_set_alpn_protos(ssl, sni_passthrough_alpn_openvpn,
                            sizeof(sni_passthrough_alpn_openvpn)) != 0)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 7");

        goto cleanup;
    }

                msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 8");

    int handshake_ret = SSL_do_handshake(ssl);
    if (handshake_ret != 1)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 9");

        int ssl_err = SSL_get_error(ssl, handshake_ret);
                char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    msg(M_NONFATAL, "--sni-passthrough-hostname: SSL_do_handshake failed: %s", err_buf);

        if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
        {
                        msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 10");

            goto cleanup;
        }
        else
        {

                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 11 : %d",ssl_err);
                            }


    }

    BIO *wbio_peek = SSL_get_wbio(ssl);
    if (!wbio_peek)
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 12");

        goto cleanup;
    }
    else
    {
                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 13");

        size_t pending = (size_t)BIO_ctrl_pending(wbio_peek);
        if (!pending || pending > bufsz)
        {
            msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 14: pending=%zu bufsz=%zu", pending, bufsz);
            goto cleanup;
        }

                    msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 15");

        int n = BIO_read(wbio_peek, buf, (int)pending);
        if (n <= 0 || (size_t)n != pending)
        {
                        msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 16");

            goto cleanup;
        }
            msg(M_NONFATAL,"--sni-passthrough-hostname: sni_passthrough_build_client_hello 17 : n=%i",n);

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
    uint8_t buf[4096];
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












int matched = 0;

static int sni_passthrough_alpn_cb(SSL *ssl, const unsigned char **out,
                   unsigned char *outlen, const unsigned char *in,
                   unsigned int inlen, void *arg) {
    if (SSL_select_next_proto((unsigned char **)out, outlen,
            sni_passthrough_alpn_openvpn,
            sizeof(sni_passthrough_alpn_openvpn), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        matched = 1;
                            msg(M_WARN,"--sni-passthrough-server: sni_passthrough_alpn_cb matched");

    }
    else
    {
                    msg(M_WARN,"--sni-passthrough-server: sni_passthrough_alpn_cb else");

    }
    return SSL_TLSEXT_ERR_OK;
}

int sni_passthrough_check_packet(const unsigned char *pkt, int pkt_len) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    /* Force TLS 1.2: the ALPN callback fires during the unencrypted ServerHello
     * in TLS 1.2, before any certificate is required.  In TLS 1.3 the callback
     * only fires after the server has a certificate ready, so it never triggers
     * when we have no cert (we only want to inspect the ClientHello). */
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, sni_passthrough_alpn_cb, NULL);

    SSL *ssl = SSL_new(ctx);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);


    matched = 0;
    int consumed = 0;

    // Feed the raw ClientHello into the read BIO
    if (pkt_len > INT_MAX)
    {
       /* something is not ok with int , should not happen */
    }
    else
    {
        BIO_write(rbio, pkt, pkt_len);

        // This will parse the ClientHello and fire callbacks
        // It will "fail" (no full handshake), but that's fine
        SSL_accept(ssl);

        size_t remaining = BIO_ctrl_pending(SSL_get_rbio(ssl));
        /* remaining == 0 means all bytes consumed, which is valid */
        if (remaining <= (size_t)pkt_len)
        {
            consumed = pkt_len - (int)remaining;
        }
        else
        {
            msg(M_WARN,"--sni-passthrough-server: BIO_ctrl_pending returned %zu > pkt_len %d", remaining, pkt_len);
        }

        msg(M_INFO,"--sni-passthrough-server: SSL_accept SNI routing header %d bytes of %d", consumed,pkt_len);
    }

    SSL_free(ssl);      // frees BIOs too
    SSL_CTX_free(ctx);

    if (matched)  /* 1 = "openvpn" was in the ALPN list */
    {
        if (consumed )
        {
                    msg(M_INFO,"--sni-passthrough-server: sni_passthrough_check_packet consumed");

            return consumed;
        }
        else
        {
            msg(M_WARN,"--sni-passthrough-server: routing header found but not consumed");
            return 0;
        }
    }
    else
    {
                            msg(M_INFO,"--sni-passthrough-server: sni_passthrough_check_packet not matched");

        return 0;
    }
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
    if (sb->buf.len >= 5)
    {
        if (BPTR(&sb->buf)[0] != 0x16) /* quick test before firing openssl on the packet */
        {
            /* client without --sni-passthrough-hostname. */
            msg(M_INFO, "--sni-passthrough-server: client without routing header");
            sb->sni_passthrough_state = SNI_PT_DISABLED;
            return false;
        }
        else
        {
          /* assuming the first packet is always complete, like port-share do. */
            const uint8_t *hdr = BPTR(&sb->buf);

            int sni_total = sni_passthrough_check_packet(hdr, sb->buf.len);

                                msg(M_INFO,"--sni-passthrough-server: sni_passthrough_check_packet SNI routing header %d bytes of %d buffer", sni_total,sb->buf.len);

            if (sni_total == 0)
            {
                /* nothing found */
                return false;

            }
            else if (sb->buf.len < sni_total)
            {
                /* Not enough data yet; should not happend. */
                                msg(M_INFO,"--sni-passthrough-server: cant discard SNI routing header %d bytes of %d buffer", sni_total,sb->buf.len);

                return false;
            }
            else
            {
                /* Full routing header received; discard it and reset the buffer so
                * normal OpenVPN stream parsing sees a clean slate. */
                int remaining = sb->buf.len - sni_total;
                msg(M_INFO,"--sni-passthrough-server: discarded SNI routing header %d bytes of %d buffer", sni_total,sb->buf.len);

                uint8_t *src = BPTR(&sb->buf) + sni_total;
                sb->buf.len = remaining;
                if (remaining > 0)
                {
                    memmove(BPTR(&sb->buf), src, remaining);
                }
                sb->sni_passthrough_state = SNI_PT_SUCCESS;
                /* Fall through to normal OpenVPN stream parsing. */
                return true;

            }
        }
    }

    return false;
}





#endif /* SNI_PASSTHROUGH */
