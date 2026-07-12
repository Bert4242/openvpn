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

#include "sni_gateway_tls.h"

#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER)

#include "openssl_compat.h"
#include "error.h"
#include "sig.h"
#include "fdmisc.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/*
 * --sni-gateway tls: client-side userspace TLS wrapper around an OpenVPN TCP
 * stream.  See sni_gateway_tls.h for the high-level description.
 *
 * Design: memory-BIO-over-the-event-loop.
 *
 * The SSL object is fed by a BIO pair.  One end of the pair (ssl_bio) is
 * handed to the SSL object as both its rbio and wbio; the other end (net_bio)
 * is the "network side" that we shuttle ciphertext through:
 *
 *      OpenVPN plaintext  <->  SSL  <->  ssl_bio  <=BIO pair=>  net_bio  <->  fd
 *
 * The fd is NEVER handed to OpenSSL.  It stays owned by OpenVPN's non-blocking
 * event loop.  On the read path we recv() ciphertext and BIO_write() it into
 * net_bio; on the write path we BIO_read() ciphertext out of net_bio and
 * send() it.  This keeps the socket fully compatible with OpenVPN's
 * select()/poll() driven scheduler (which is level-triggered, so as long as
 * unread ciphertext remains on the socket we will be called again).
 *
 * Only the blocking handshake (done up-front, before the fd is switched to
 * non-blocking) drives its own select() loop so that --server-poll-timeout and
 * signals still interrupt a stuck gateway, mirroring establish_http_proxy_
 * passthru().
 */

struct sni_gw_tls
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *net_bio; /* network side of the BIO pair; SSL owns the app side */

    /*
     * FIFO of ciphertext produced by SSL_write() that has not yet been
     * accepted by the kernel socket buffer (send() returned EAGAIN).  Bytes
     * between [offset, offset+len) are pending; they MUST be sent, in order,
     * before any newly produced ciphertext, or the TLS record stream corrupts.
     * data is a plain malloc()/realloc() block (not alloc_buf()) so we can grow
     * it on demand.
     */
    struct buffer out_ciphertext;

    bool handshake_done;
};

/* Scratch size for moving ciphertext between the socket and net_bio. */
#define SNI_GW_TLS_SCRATCH 16384

/* -------------------------------------------------------------------------- */
/* out_ciphertext FIFO helpers                                                */
/* -------------------------------------------------------------------------- */

/* Append n bytes of ciphertext to the tail of the pending FIFO, growing it as
 * needed.  Returns false only on allocation failure. */
static bool
gw_out_append(struct sni_gw_tls *t, const uint8_t *data, int n)
{
    struct buffer *b = &t->out_ciphertext;

    if (n <= 0)
    {
        return true;
    }

    /* Reclaim already-consumed head space by shifting unread data to the
     * front; only grow the allocation if that is still not enough. */
    if (b->offset + b->len + n > b->capacity)
    {
        if (b->len > 0 && b->offset > 0)
        {
            memmove(b->data, b->data + b->offset, (size_t)b->len);
        }
        b->offset = 0;

        if (b->len + n > b->capacity)
        {
            int newcap = b->capacity > 0 ? b->capacity : SNI_GW_TLS_SCRATCH;
            while (newcap < b->len + n)
            {
                newcap *= 2;
            }
            uint8_t *nd = realloc(b->data, (size_t)newcap);
            if (!nd)
            {
                return false;
            }
            b->data = nd;
            b->capacity = newcap;
        }
    }

    memcpy(b->data + b->offset + b->len, data, (size_t)n);
    b->len += n;
    return true;
}

/*
 * Try to send as much of the pending ciphertext FIFO as the non-blocking
 * socket will accept.  Consumed bytes are removed from the head.
 * Returns:
 *   true  -- FIFO fully drained (nothing pending).
 *   false -- bytes still pending (EAGAIN) OR a fatal send error occurred;
 *            *fatal is set to distinguish the two.
 */
static bool
gw_out_flush(struct sni_gw_tls *t, socket_descriptor_t sd, bool *fatal)
{
    struct buffer *b = &t->out_ciphertext;
    *fatal = false;

    while (b->len > 0)
    {
        ssize_t s = send(sd, b->data + b->offset, (size_t)b->len, MSG_NOSIGNAL);
        if (s > 0)
        {
            b->offset += (int)s;
            b->len -= (int)s;
        }
        else
        {
            int e = openvpn_errno();
            if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
            {
                return false; /* not fatal, retry later */
            }
            msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: send() of ciphertext failed");
            *fatal = true;
            return false;
        }
    }

    /* Fully drained -- reset the FIFO so it stays compact. */
    b->offset = 0;
    b->len = 0;
    return true;
}

/* -------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* -------------------------------------------------------------------------- */

struct sni_gw_tls *
sni_gw_tls_new(void)
{
    struct sni_gw_tls *t = calloc(1, sizeof(*t));
    return t;
}

void
sni_gw_tls_free(struct sni_gw_tls *t)
{
    if (!t)
    {
        return;
    }
    if (t->ssl)
    {
        SSL_free(t->ssl); /* also frees the ssl-side BIO of the pair */
    }
    if (t->net_bio)
    {
        BIO_free(t->net_bio);
    }
    if (t->ctx)
    {
        SSL_CTX_free(t->ctx);
    }
    free(t->out_ciphertext.data);
    free(t);
}

/* -------------------------------------------------------------------------- */
/* ALPN wire-format helper                                                    */
/* -------------------------------------------------------------------------- */

/*
 * Build the length-prefixed ALPN protocol list expected by
 * SSL_set_alpn_protos() ( [len][name] repeated ).  Writes into out (already
 * set up for writing).  Returns false on overflow / an over-long token.
 */
static bool
gw_build_alpn_wire(struct buffer *out, const char *const *alpn_list, int alpn_count)
{
    for (int i = 0; i < alpn_count; i++)
    {
        const char *name = alpn_list[i];
        if (!name || !*name)
        {
            continue;
        }
        size_t name_len = strlen(name);
        if (name_len > 255)
        {
            return false;
        }
        if (!buf_write_u8(out, (uint8_t)name_len) || !buf_write(out, name, name_len))
        {
            return false;
        }
    }
    return true;
}

/* -------------------------------------------------------------------------- */
/* Blocking handshake                                                         */
/* -------------------------------------------------------------------------- */

/*
 * Move any ciphertext SSL wants to send from net_bio to the (blocking-time)
 * socket, waiting for writability with the poll timeout / signal.  Returns
 * false on timeout, signal, or socket error.
 */
static bool
gw_handshake_flush_out(struct sni_gw_tls *t, socket_descriptor_t sd,
                       volatile int *signal_received, int poll_timeout)
{
    uint8_t scratch[SNI_GW_TLS_SCRATCH];

    while (BIO_ctrl_pending(t->net_bio) > 0)
    {
        int n = BIO_read(t->net_bio, scratch, (int)sizeof(scratch));
        if (n <= 0)
        {
            return true; /* nothing to send right now */
        }

        int sent = 0;
        while (sent < n)
        {
            fd_set writes;
            struct timeval tv;
            FD_ZERO(&writes);
            openvpn_fd_set(sd, &writes);
            tv.tv_sec = poll_timeout;
            tv.tv_usec = 0;

            int status = openvpn_select(sd + 1, NULL, &writes, NULL, &tv);
            get_signal(signal_received);
            if (*signal_received)
            {
                return false;
            }
            if (status == 0)
            {
                msg(D_LINK_ERRORS, "sni-gateway tls: handshake write timeout");
                return false;
            }
            if (status < 0)
            {
                msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: handshake select() failed");
                return false;
            }

            ssize_t s = send(sd, scratch + sent, (size_t)(n - sent), MSG_NOSIGNAL);
            if (s > 0)
            {
                sent += (int)s;
            }
            else
            {
                int e = openvpn_errno();
                if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
                {
                    continue;
                }
                msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: handshake send() failed");
                return false;
            }
        }
    }
    return true;
}

/*
 * Wait for the socket to become readable (poll timeout / signal), recv one
 * chunk of ciphertext, and feed it into net_bio.  Returns false on timeout,
 * signal, peer close, or socket error.
 */
static bool
gw_handshake_fill_in(struct sni_gw_tls *t, socket_descriptor_t sd,
                     volatile int *signal_received, int poll_timeout)
{
    uint8_t scratch[SNI_GW_TLS_SCRATCH];

    fd_set reads;
    struct timeval tv;
    FD_ZERO(&reads);
    openvpn_fd_set(sd, &reads);
    tv.tv_sec = poll_timeout;
    tv.tv_usec = 0;

    int status = openvpn_select(sd + 1, &reads, NULL, NULL, &tv);
    get_signal(signal_received);
    if (*signal_received)
    {
        return false;
    }
    if (status == 0)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: handshake read timeout");
        return false;
    }
    if (status < 0)
    {
        msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: handshake select() failed");
        return false;
    }

    ssize_t r = recv(sd, scratch, sizeof(scratch), MSG_NOSIGNAL);
    if (r == 0)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: gateway closed connection during handshake");
        return false;
    }
    if (r < 0)
    {
        int e = openvpn_errno();
        if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
        {
            return true; /* spurious wakeup, try again */
        }
        msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: handshake recv() failed");
        return false;
    }

    int off = 0;
    while (off < (int)r)
    {
        int w = BIO_write(t->net_bio, scratch + off, (int)r - off);
        if (w <= 0)
        {
            /* net_bio full without SSL draining it: cannot make progress. */
            msg(D_LINK_ERRORS, "sni-gateway tls: handshake BIO_write stalled");
            return false;
        }
        off += w;
    }
    return true;
}

bool
sni_gw_tls_client_handshake(struct sni_gw_tls *t, socket_descriptor_t sd,
                            const char *host,
                            const char *const *alpn_list, int alpn_count,
                            const char *ca_file, bool no_verify,
                            volatile int *signal_received, int server_poll_timeout)
{
    BIO *ssl_bio = NULL;
    int poll_timeout = server_poll_timeout > 0 ? server_poll_timeout : 10;

    if (!host || !*host)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: no --sni-gateway-host set");
        return false;
    }

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: SSL_CTX_new failed");
        goto err;
    }
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);

    if (!no_verify)
    {
        if (ca_file)
        {
            if (SSL_CTX_load_verify_locations(t->ctx, ca_file, NULL) != 1)
            {
                msg(D_LINK_ERRORS, "sni-gateway tls: cannot load CA file '%s'", ca_file);
                goto err;
            }
        }
        else if (SSL_CTX_set_default_verify_paths(t->ctx) != 1)
        {
            msg(D_LINK_ERRORS, "sni-gateway tls: cannot load system trust store");
            goto err;
        }
    }

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: SSL_new failed");
        goto err;
    }

    /* SNI */
    if (!SSL_set_tlsext_host_name(t->ssl, host))
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: SSL_set_tlsext_host_name failed");
        goto err;
    }

    /* Certificate verification against the gateway hostname. */
    if (no_verify)
    {
        SSL_set_verify(t->ssl, SSL_VERIFY_NONE, NULL);
    }
    else
    {
        if (SSL_set1_host(t->ssl, host) != 1)
        {
            msg(D_LINK_ERRORS, "sni-gateway tls: SSL_set1_host failed");
            goto err;
        }
        SSL_set_verify(t->ssl, SSL_VERIFY_PEER, NULL);
    }

    /* Optional ALPN advertised in the genuine handshake. */
    if (alpn_list && alpn_count > 0)
    {
        uint8_t alpn_raw[4096];
        struct buffer alpn_wire;
        buf_set_write(&alpn_wire, alpn_raw, sizeof(alpn_raw));
        if (!gw_build_alpn_wire(&alpn_wire, alpn_list, alpn_count) || !BLEN(&alpn_wire))
        {
            msg(D_LINK_ERRORS, "sni-gateway tls: failed to build ALPN list");
            goto err;
        }
        if (SSL_set_alpn_protos(t->ssl, BPTR(&alpn_wire), (unsigned int)BLEN(&alpn_wire)) != 0)
        {
            msg(D_LINK_ERRORS, "sni-gateway tls: SSL_set_alpn_protos failed");
            goto err;
        }
    }

    /* Wire up the BIO pair: ssl_bio -> SSL, net_bio -> us. */
    if (BIO_new_bio_pair(&ssl_bio, SNI_GW_TLS_SCRATCH, &t->net_bio, SNI_GW_TLS_SCRATCH) != 1)
    {
        msg(D_LINK_ERRORS, "sni-gateway tls: BIO_new_bio_pair failed");
        ssl_bio = NULL;
        goto err;
    }
    SSL_set_bio(t->ssl, ssl_bio, ssl_bio); /* SSL takes ownership of ssl_bio */
    ssl_bio = NULL;
    SSL_set_connect_state(t->ssl);

    /* Drive the handshake, shuttling ciphertext via net_bio. */
    while (true)
    {
        int r = SSL_do_handshake(t->ssl);
        if (r == 1)
        {
            break; /* handshake complete */
        }

        int err = SSL_get_error(t->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            /* Always flush anything SSL wants to send first... */
            if (!gw_handshake_flush_out(t, sd, signal_received, poll_timeout))
            {
                goto err;
            }
            /* ...then, if it is waiting on the peer, read more ciphertext. */
            if (err == SSL_ERROR_WANT_READ)
            {
                if (!gw_handshake_fill_in(t, sd, signal_received, poll_timeout))
                {
                    goto err;
                }
            }
        }
        else
        {
            char buf[256];
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
            msg(D_LINK_ERRORS, "sni-gateway tls: handshake failed: %s", buf);
            goto err;
        }
    }

    /* Flush any final handshake ciphertext (e.g. client Finished) to the wire. */
    if (!gw_handshake_flush_out(t, sd, signal_received, poll_timeout))
    {
        goto err;
    }

    if (!no_verify)
    {
        long vr = SSL_get_verify_result(t->ssl);
        if (vr != X509_V_OK)
        {
            msg(D_LINK_ERRORS, "sni-gateway tls: certificate verification failed: %s",
                X509_verify_cert_error_string(vr));
            goto err;
        }
    }

    t->handshake_done = true;
    msg(D_HANDSHAKE, "sni-gateway tls: TLS handshake to '%s' complete%s", host,
        no_verify ? " (verification disabled)" : "");
    return true;

err:
    if (ssl_bio)
    {
        BIO_free(ssl_bio);
    }
    return false;
}

/* -------------------------------------------------------------------------- */
/* Steady-state read                                                          */
/* -------------------------------------------------------------------------- */

ssize_t
sni_gw_tls_read(struct sni_gw_tls *t, socket_descriptor_t sd, struct buffer *buf)
{
    uint8_t scratch[SNI_GW_TLS_SCRATCH];

    /*
     * Pull whatever ciphertext the (non-blocking) socket has and feed net_bio,
     * bounded by the space net_bio can currently accept.  The event loop is
     * level-triggered, so if more ciphertext remains on the socket than net_bio
     * can hold this iteration, we will simply be called again.
     */
    size_t space = (size_t)BIO_ctrl_get_write_guarantee(t->net_bio);
    if (space > 0)
    {
        size_t want = space < sizeof(scratch) ? space : sizeof(scratch);
        ssize_t r = recv(sd, scratch, want, MSG_NOSIGNAL);
        if (r == 0)
        {
            /* Peer closed the TCP connection. */
            return -1;
        }
        else if (r < 0)
        {
            int e = openvpn_errno();
            if (e != EAGAIN && e != EWOULDBLOCK && e != EINTR)
            {
                msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway tls: recv() failed");
                return -1;
            }
            /* EAGAIN: no new ciphertext, but SSL may still have buffered data. */
        }
        else
        {
            int off = 0;
            while (off < (int)r)
            {
                int w = BIO_write(t->net_bio, scratch + off, (int)r - off);
                if (w <= 0)
                {
                    break; /* net_bio full; remainder waits for the next call */
                }
                off += w;
            }
        }
    }

    /*
     * Decrypt into the fragment region [BPTR(buf), BPTR(buf)+BLEN(buf)).
     * Matching the raw recv() path exactly: stream_buf_get_next() hands us a
     * buffer whose *len* (not forward-capacity) is the amount of space to fill,
     * so we must read up to BLEN(buf) bytes -- the raw path passes BLENZ(&frag)
     * to recv() for the same reason.
     */
    int cap = BLEN(buf);
    if (cap <= 0)
    {
        return 0;
    }
    int n = SSL_read(t->ssl, BPTR(buf), cap);
    if (n > 0)
    {
        return n;
    }

    int err = SSL_get_error(t->ssl, n);
    switch (err)
    {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return 0; /* no complete plaintext yet -- packet still incomplete */

        case SSL_ERROR_ZERO_RETURN:
            /* Clean TLS shutdown from the peer. */
            return -1;

        default:
        {
            char e[256];
            unsigned long code = ERR_get_error();
            if (code)
            {
                ERR_error_string_n(code, e, sizeof(e));
                msg(D_LINK_ERRORS, "sni-gateway tls: SSL_read failed: %s", e);
            }
            else
            {
                msg(D_LINK_ERRORS, "sni-gateway tls: SSL_read failed (connection reset)");
            }
            return -1;
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Steady-state write                                                         */
/* -------------------------------------------------------------------------- */

/*
 * Non-blocking partial-ciphertext-write strategy
 * ----------------------------------------------
 * OpenVPN's TCP output path (process_outgoing_link) resets its to_link buffer
 * unconditionally after a single write attempt: a write returning EAGAIN drops
 * the packet, it is NOT retried with the same buffer.  For a raw socket that is
 * fine because OpenVPN only writes when the socket is already writable.  For
 * TLS it is a trap: SSL_write() consumes the plaintext into the TLS record
 * stream *irreversibly*, so we can never report "try again later" for a packet
 * we have already encrypted, and we must never drop encrypted bytes or send
 * them out of order.
 *
 * Therefore this function always *accepts* the plaintext in full:
 *   1. First flush any ciphertext left over from a previous EAGAIN (FIFO head).
 *      If that still cannot fully drain, we must not produce more ciphertext
 *      out of order -- but we also must not drop this packet.  So we buffer the
 *      new plaintext's ciphertext behind it: SSL_write() then append to the
 *      FIFO tail, and report the plaintext accepted.  Ordering is preserved
 *      because we always send strictly from the FIFO head.
 *   2. SSL_write() the plaintext (a memory BIO never does a partial write for
 *      the packet sizes OpenVPN uses).
 *   3. Move the freshly produced ciphertext from net_bio onto the FIFO tail.
 *   4. Try to send the FIFO (head-first) until the socket says EAGAIN; keep the
 *      unsent remainder for the next call.
 *   5. Return the plaintext byte count (accepted).
 *
 * The pending FIFO drains on subsequent writes.  A fatal send()/SSL error
 * returns -1 so the caller tears the connection down.
 */
ssize_t
sni_gw_tls_write(struct sni_gw_tls *t, socket_descriptor_t sd, struct buffer *buf)
{
    const int plaintext_len = BLEN(buf);
    bool fatal = false;

    /* 1. Drain previously-pending ciphertext first (preserves ordering). */
    gw_out_flush(t, sd, &fatal);
    if (fatal)
    {
        return -1;
    }

    /* 2. Encrypt the new plaintext. */
    if (plaintext_len > 0)
    {
        int w = SSL_write(t->ssl, BPTR(buf), plaintext_len);
        if (w <= 0)
        {
            int err = SSL_get_error(t->ssl, w);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                /* Renegotiation stall: extremely unlikely for TLS1.2/1.3 with
                 * our config.  Report a soft failure so the packet is dropped
                 * (control channel will retransmit) rather than corrupting the
                 * stream. */
                return -1;
            }
            char e[256];
            ERR_error_string_n(ERR_get_error(), e, sizeof(e));
            msg(D_LINK_ERRORS, "sni-gateway tls: SSL_write failed: %s", e);
            return -1;
        }
        /* For a memory BIO SSL_write is all-or-nothing at these sizes. */

        /* 3. Move produced ciphertext onto the FIFO tail. */
        uint8_t scratch[SNI_GW_TLS_SCRATCH];
        int c;
        while ((c = BIO_read(t->net_bio, scratch, (int)sizeof(scratch))) > 0)
        {
            if (!gw_out_append(t, scratch, c))
            {
                msg(D_LINK_ERRORS, "sni-gateway tls: out of memory buffering ciphertext");
                return -1;
            }
        }
    }

    /* 4. Try to push the FIFO out; remainder stays buffered for next time. */
    gw_out_flush(t, sd, &fatal);
    if (fatal)
    {
        return -1;
    }

    /* 5. Plaintext was fully accepted into the TLS stream. */
    return plaintext_len;
}

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */
