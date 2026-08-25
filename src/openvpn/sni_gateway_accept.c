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

#include "sni_gateway_accept.h"

#include "socket.h"
#include "error.h"
#include "sig.h"
#include "fdmisc.h"

/* Bounded number of MSG_PEEK attempts before giving up on classification. */
#define SNI_GW_ACCEPT_MAX_ATTEMPTS 50

/*
 * Brief backoff between re-peeks that saw no new bytes.  MSG_PEEK on a
 * blocking socket returns immediately with whatever is already queued
 * (it does not wait for the requested length), so if a slow peer splits
 * "GET " across multiple TCP segments, re-peeking in a tight loop would
 * spin at full CPU between segments instead of actually waiting.
 */
static void
sni_gw_accept_backoff(void)
{
#if defined(_WIN32)
    Sleep(20);
#else
    usleep(20 * 1000);
#endif
}

enum sni_gw_accept_class
sni_gw_accept_classify_bytes(const uint8_t *peek, int peek_len)
{
    if (peek_len < 1)
    {
        return SNI_GW_ACCEPT_NEED_MORE;
    }
    if (peek[0] == 0x16)
    {
        return SNI_GW_ACCEPT_SNI; /* decided off the first byte alone */
    }

    /*
     * Byte-by-byte probe against "GET ", mirroring the same style used in
     * sni_gw_http_check_and_consume_request() (sni_gateway_http.c) so a
     * raw-OpenVPN/sni-tls client (whose first bytes are a binary length
     * prefix, never "GET ") is recognized as soon as the first
     * non-matching byte arrives.
     */
    static const uint8_t get_prefix[4] = { 'G', 'E', 'T', ' ' };
    int probe = peek_len < 4 ? peek_len : 4;
    for (int i = 0; i < probe; i++)
    {
        if (peek[i] != get_prefix[i])
        {
            return SNI_GW_ACCEPT_OTHER;
        }
    }
    if (peek_len < 4)
    {
        return SNI_GW_ACCEPT_NEED_MORE; /* matches so far, need more bytes */
    }
    return SNI_GW_ACCEPT_HTTP;
}

enum sni_gw_accept_class
sni_gw_accept_classify_fd(socket_descriptor_t sd, bool *error,
                          volatile int *signal_received, int poll_timeout)
{
    *error = false;
    ssize_t prev_n = -1;

    for (int attempt = 0; attempt < SNI_GW_ACCEPT_MAX_ATTEMPTS; attempt++)
    {
        /* recv(MSG_PEEK) on a still-blocking socket blocks just like a plain
         * recv() when zero bytes are queued -- it only skips waiting for the
         * full requested length once at least one byte has arrived.  Gate it
         * behind a bounded select() so a peer that opens the connection and
         * sends nothing can't hang this call (and, with it, the whole
         * single-threaded server) forever. */
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
            *error = true;
            return SNI_GW_ACCEPT_OTHER;
        }
        if (status == 0)
        {
            msg(D_LINK_ERRORS,
                "--sni-gateway-server auto: timed out waiting for bytes to classify connection");
            *error = true;
            return SNI_GW_ACCEPT_OTHER;
        }
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-gateway-server auto: select() failed while classifying connection");
            *error = true;
            return SNI_GW_ACCEPT_OTHER;
        }

        uint8_t buf[4];
        ssize_t n = recv(sd, (void *)buf, sizeof(buf), MSG_PEEK);
        if (n < 0)
        {
            int e = openvpn_errno();
            if (e == EINTR || e == EAGAIN || e == EWOULDBLOCK)
            {
                continue;
            }
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-gateway-server auto: recv(MSG_PEEK) failed while classifying connection");
            *error = true;
            return SNI_GW_ACCEPT_OTHER;
        }
        if (n == 0)
        {
            msg(D_LINK_ERRORS,
                "--sni-gateway-server auto: connection closed before enough bytes to classify");
            *error = true;
            return SNI_GW_ACCEPT_OTHER;
        }

        enum sni_gw_accept_class cls = sni_gw_accept_classify_bytes(buf, (int)n);
        if (cls != SNI_GW_ACCEPT_NEED_MORE)
        {
            return cls;
        }

        if (n == prev_n)
        {
            /* No new bytes arrived since the last peek: matched "GET " so
             * far but the peer hasn't finished sending it yet. */
            sni_gw_accept_backoff();
        }
        prev_n = n;
    }

    msg(D_LINK_ERRORS,
        "--sni-gateway-server auto: timed out classifying connection (no decision after %d attempts)",
        SNI_GW_ACCEPT_MAX_ATTEMPTS);
    *error = true;
    return SNI_GW_ACCEPT_OTHER;
}
