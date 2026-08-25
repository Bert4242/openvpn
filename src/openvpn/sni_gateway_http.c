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

#include "sni_gateway_http.h"

#include "socket.h"
#include "error.h"
#include "fdmisc.h"
#include "sig.h"

/*
 * Upper bound on the HTTP Upgrade request we are willing to buffer before the
 * terminating blank line.  The genuine request is well under 200 bytes; this
 * cap just stops a misbehaving/hostile peer from making us buffer forever.
 */
#define SNI_GW_HTTP_MAX_REQUEST 4096

/* ------------------------------------------------------------------------- */
/* Response builder                                                           */
/* ------------------------------------------------------------------------- */

size_t
sni_gw_http_build_101(char *buf, size_t bufsz, const char *token)
{
    if (!buf || bufsz == 0 || !token || !*token)
    {
        return 0;
    }

    int n = snprintf(buf, bufsz,
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Connection: Upgrade\r\n"
                     "Upgrade: %s\r\n"
                     "\r\n",
                     token);
    if (n < 0 || (size_t)n >= bufsz)
    {
        return 0; /* encoding error or truncated -> overflow */
    }
    return (size_t)n;
}

/* ------------------------------------------------------------------------- */
/* Client request builder                                                     */
/* ------------------------------------------------------------------------- */

size_t
sni_gw_http_build_upgrade(char *buf, size_t bufsz, const char *host, const char *path,
                          const char *token)
{
    if (!buf || bufsz == 0 || !host || !*host || !path || path[0] != '/'
        || !token || !*token)
    {
        return 0;
    }

    int n = snprintf(buf, bufsz,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: Upgrade\r\n"
                     "Upgrade: %s\r\n"
                     "\r\n",
                     path, host, token);
    if (n < 0 || (size_t)n >= bufsz)
    {
        return 0; /* encoding error or truncated -> overflow */
    }
    return (size_t)n;
}

/* ------------------------------------------------------------------------- */
/* Client-side: shared "read the 101 response" reader                        */
/* ------------------------------------------------------------------------- */

bool
sni_gw_http_client_read_101(sni_gw_http_read_byte_fn read_byte, void *ctx,
                            volatile int *signal_received, int poll_timeout,
                            const char *log_prefix)
{
    char resp[1024];
    int rlen = 0;
    bool complete = false;

    while (rlen < (int)sizeof(resp))
    {
        uint8_t byte;
        if (!read_byte(ctx, &byte, signal_received, poll_timeout))
        {
            return false;
        }
        resp[rlen++] = (char)byte;
        if (rlen >= 4
            && resp[rlen - 4] == '\r' && resp[rlen - 3] == '\n'
            && resp[rlen - 2] == '\r' && resp[rlen - 1] == '\n')
        {
            complete = true;
            break;
        }
    }
    if (!complete)
    {
        msg(D_LINK_ERRORS, "%s: 101 response header too large / not terminated", log_prefix);
        return false;
    }

    static const char expect[] = "HTTP/1.1 101";
    if (rlen < (int)(sizeof(expect) - 1)
        || memcmp(resp, expect, sizeof(expect) - 1) != 0)
    {
        int line = 0;
        while (line < rlen && resp[line] != '\r')
        {
            line++;
        }
        msg(D_LINK_ERRORS, "%s: gateway did not return 101 (got '%.*s')",
            log_prefix, line, resp);
        return false;
    }

    return true;
}

/* ------------------------------------------------------------------------- */
/* Client-side: plain-socket Upgrade (--sni-gateway sni-http-path-upgrade)   */
/* ------------------------------------------------------------------------- */

/*
 * Blocking write of the whole buffer over a plain (still-blocking) TCP
 * socket, honoring poll_timeout/signal_received.  Mirrors gw_ssl_write_all()
 * in sni_gateway_tls.c but shuttles plaintext bytes directly with send(),
 * no TLS record layer involved.
 */
static bool
gw_plain_write_all(socket_descriptor_t sd, const void *data, int len,
                   volatile int *signal_received, int poll_timeout)
{
    int off = 0;
    while (off < len)
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
            msg(D_LINK_ERRORS, "sni-gateway http (plain): write timeout");
            return false;
        }
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway http (plain): select() failed");
            return false;
        }

        ssize_t s = send(sd, (const char *)data + off, len - off, MSG_NOSIGNAL);
        if (s > 0)
        {
            off += (int)s;
        }
        else
        {
            int e = openvpn_errno();
            if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
            {
                continue;
            }
            msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway http (plain): send() failed");
            return false;
        }
    }
    return true;
}

/*
 * Blocking read of exactly one plaintext byte, honoring
 * poll_timeout/signal_received.  Mirrors gw_ssl_read_byte()'s per-byte
 * strategy in sni_gateway_tls.c: trailing bytes the gateway coalesced into
 * the same TCP segment after the response's terminating blank line are left
 * in the kernel socket buffer for the steady-state raw recv() path -- this
 * mode never allocates a userspace FIFO to buffer them in.
 */
static bool
gw_plain_read_byte(socket_descriptor_t sd, uint8_t *out,
                   volatile int *signal_received, int poll_timeout)
{
    for (;;)
    {
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
            msg(D_LINK_ERRORS, "sni-gateway http (plain): read timeout");
            return false;
        }
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway http (plain): select() failed");
            return false;
        }

        ssize_t r = recv(sd, (char *)out, 1, MSG_NOSIGNAL);
        if (r == 1)
        {
            return true;
        }
        if (r == 0)
        {
            msg(D_LINK_ERRORS, "sni-gateway http (plain): gateway closed connection during upgrade");
            return false;
        }

        int e = openvpn_errno();
        if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
        {
            continue; /* spurious wakeup, try again */
        }
        msg(D_LINK_ERRORS | M_ERRNO, "sni-gateway http (plain): recv() failed");
        return false;
    }
}

/* Adapter matching sni_gw_http_read_byte_fn; ctx is a socket_descriptor_t *. */
static bool
plain_read_byte_adapter(void *ctx, uint8_t *out,
                        volatile int *signal_received, int poll_timeout)
{
    socket_descriptor_t sd = *(socket_descriptor_t *)ctx;
    return gw_plain_read_byte(sd, out, signal_received, poll_timeout);
}

bool
sni_gw_http_client_upgrade_plain(socket_descriptor_t sd,
                                 const char *host, const char *path,
                                 const char *token,
                                 volatile int *signal_received,
                                 int server_poll_timeout)
{
    int poll_timeout = server_poll_timeout > 0 ? server_poll_timeout : 10;

    char req[1024];
    size_t reqlen = sni_gw_http_build_upgrade(req, sizeof(req), host, path, token);
    if (reqlen == 0)
    {
        msg(D_LINK_ERRORS, "sni-gateway http (plain): could not build Upgrade request "
                           "(bad --sni-gateway-host/--sni-gateway-path?)");
        return false;
    }

    if (!gw_plain_write_all(sd, req, (int)reqlen, signal_received, poll_timeout))
    {
        return false;
    }

    if (!sni_gw_http_client_read_101(plain_read_byte_adapter, &sd, signal_received,
                                     poll_timeout, "sni-gateway http (plain)"))
    {
        return false;
    }

    msg(D_HANDSHAKE, "sni-gateway http (plain): HTTP Upgrade to '%s' path '%s' complete",
        host, path);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Server request parser                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Scan the header block [hdrs, hdrs+hdrs_len) (which starts right after the
 * request line and ends at the final blank line) for a header line
 *   Upgrade: <name>[, <name>...]
 * with a case-insensitive header name and, per RFC 7230 S6.7, a
 * comma-separated list of protocol tokens as the value.  Returns true iff
 * one list element is an EXACT case-insensitive match for token (after
 * trimming optional whitespace around commas) -- not a substring match.
 */
static bool
http_has_upgrade_token(const char *hdrs, int hdrs_len, const char *token)
{
    size_t tok_len = strlen(token);
    const char *p = hdrs;
    const char *stop = hdrs + hdrs_len;

    while (p < stop)
    {
        const char *eol = memchr(p, '\r', (size_t)(stop - p));
        if (!eol)
        {
            break;
        }
        int line_len = (int)(eol - p);
        if (line_len == 0)
        {
            break; /* blank line -> end of headers */
        }

        const char *colon = memchr(p, ':', (size_t)line_len);
        if (colon)
        {
            int name_len = (int)(colon - p);
            if (name_len == 7 && strncasecmp(p, "Upgrade", 7) == 0)
            {
                const char *v = colon + 1;
                const char *vend = eol;
                while (v < vend)
                {
                    const char *sep = memchr(v, ',', (size_t)(vend - v));
                    const char *elem_end = sep ? sep : vend;
                    const char *e_start = v;
                    const char *e_stop = elem_end;
                    while (e_start < e_stop && (*e_start == ' ' || *e_start == '\t'))
                    {
                        e_start++;
                    }
                    while (e_stop > e_start && (e_stop[-1] == ' ' || e_stop[-1] == '\t'))
                    {
                        e_stop--;
                    }
                    if ((size_t)(e_stop - e_start) == tok_len
                        && strncasecmp(e_start, token, tok_len) == 0)
                    {
                        return true;
                    }
                    v = sep ? sep + 1 : vend;
                }
            }
        }

        p = eol + 2; /* skip the CRLF (safe: memchr found '\r' before stop) */
    }
    return false;
}

int
sni_gw_http_check_and_consume_request(struct stream_buf *sb, const char *require_path,
                                      const char *token)
{
    struct buffer *b = &sb->buf;
    const char *data = (const char *)BPTR(b);
    int len = b->len;

    /*
     * Match against the "GET " prefix byte by byte so a raw-OpenVPN client
     * (whose first bytes are a binary length prefix, never "GET ") is detected
     * as soon as the first non-matching byte arrives.
     */
    static const char get_prefix[4] = { 'G', 'E', 'T', ' ' };
    int probe = len < 4 ? len : 4;
    for (int i = 0; i < probe; i++)
    {
        if (data[i] != get_prefix[i])
        {
            msg(M_INFO, "--sni-gateway-server sni-http-path-upgrade: non-HTTP client, proceeding as OpenVPN");
            sb->sni_gw_http_state = SNI_GW_HTTP_DISABLED;
            return -1; /* sb->error left false -> proceed as normal OpenVPN */
        }
    }
    if (len < 4)
    {
        return 0; /* "GET " not fully seen yet */
    }

    /* Locate the terminating blank line (CRLF CRLF). */
    const char *end = NULL;
    for (int i = 0; i + 4 <= len; i++)
    {
        if (data[i] == '\r' && data[i + 1] == '\n'
            && data[i + 2] == '\r' && data[i + 3] == '\n')
        {
            end = data + i + 4;
            break;
        }
    }
    if (!end)
    {
        if (len > SNI_GW_HTTP_MAX_REQUEST)
        {
            msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: request header exceeds %d bytes, rejecting",
                SNI_GW_HTTP_MAX_REQUEST);
            sb->error = true;
            sb->sni_gw_http_state = SNI_GW_HTTP_DISABLED;
            return -1;
        }
        return 0; /* need more */
    }

    int request_len = (int)(end - data);

    /* Parse the request line "GET <path> HTTP/1.1". */
    const char *line_end = memchr(data, '\r', (size_t)request_len);
    if (!line_end)
    {
        goto reject;                   /* cannot happen (CRLFCRLF found) but be defensive */
    }
    const char *path_start = data + 4; /* just past "GET " */
    const char *sp = memchr(path_start, ' ', (size_t)(line_end - path_start));
    if (!sp || sp == path_start)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: malformed request line, rejecting");
        goto reject;
    }
    int path_len = (int)(sp - path_start);
    if (path_start[0] != '/')
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: request path does not start with '/', rejecting");
        goto reject;
    }

    /* Version token must be exactly "HTTP/1.1". */
    const char *ver = sp + 1;
    int ver_len = (int)(line_end - ver);
    if (ver_len != 8 || memcmp(ver, "HTTP/1.1", 8) != 0)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: unsupported HTTP version, rejecting");
        goto reject;
    }

    /* Require a matching Upgrade: header. */
    const char *hdrs = line_end + 2; /* past the request line's CRLF */
    int hdrs_len = (int)(end - hdrs);
    if (!http_has_upgrade_token(hdrs, hdrs_len, token))
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: missing or mismatched "
                    "'Upgrade: %s' header, rejecting",
            token);
        goto reject;
    }

    /* Optional exact path enforcement. */
    if (require_path)
    {
        int rp_len = (int)strlen(require_path);
        if (rp_len != path_len || memcmp(path_start, require_path, (size_t)path_len) != 0)
        {
            msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: request path does not match "
                        "--sni-gateway-server-path, rejecting");
            goto reject;
        }
    }

    /* Success: strip the consumed request, leaving any trailing OpenVPN bytes. */
    {
        int remaining = len - request_len;
        msg(M_INFO, "--sni-gateway-server sni-http-path-upgrade: consumed %d-byte Upgrade request (path '%.*s')",
            request_len, path_len, path_start);
        if (remaining > 0)
        {
            memmove(BPTR(b), BPTR(b) + request_len, (size_t)remaining);
        }
        b->len = remaining;
        sb->sni_gw_http_state = SNI_GW_HTTP_SUCCESS;
        return request_len;
    }

reject:
    sb->error = true;
    sb->sni_gw_http_state = SNI_GW_HTTP_DISABLED;
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Server 101 emitter + blocking Upgrade acceptor                             */
/* ------------------------------------------------------------------------- */

bool
sni_gw_http_send_101(socket_descriptor_t sd, const char *token)
{
    char resp[256];
    size_t total = sni_gw_http_build_101(resp, sizeof(resp), token);
    if (total == 0)
    {
        msg(D_LINK_ERRORS, "--sni-gateway-server sni-http-path-upgrade: could not build "
                           "101 response (bad --sni-gateway-server-upgrade-token?)");
        return false;
    }
    const char *p = resp;
    size_t sent = 0;
    int attempts = 0;

    while (sent < total)
    {
        ssize_t s = send(sd, p + sent, (int)(total - sent), MSG_NOSIGNAL);
        if (s > 0)
        {
            sent += (size_t)s;
            continue;
        }

        int e = openvpn_errno();
        if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
        {
            if (++attempts > 100)
            {
                msg(D_LINK_ERRORS, "--sni-gateway-server sni-http-path-upgrade: timed out sending 101 response");
                return false;
            }
            /* Wait (briefly, bounded) for the socket to drain. */
            fd_set writes;
            struct timeval tv;
            FD_ZERO(&writes);
            openvpn_fd_set(sd, &writes);
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            openvpn_select(sd + 1, NULL, &writes, NULL, &tv);
            continue;
        }

        msg(D_LINK_ERRORS | M_ERRNO, "--sni-gateway-server sni-http-path-upgrade: send() of 101 response failed");
        return false;
    }
    return true;
}

bool
sni_gw_http_server_accept_upgrade(socket_descriptor_t sd, const char *require_path,
                                  const char *token,
                                  volatile int *signal_received, int poll_timeout)
{
    char buf[SNI_GW_HTTP_MAX_REQUEST];
    int total = 0;
    int end_pos = -1; /* byte offset just past the CRLFCRLF terminator */

    /* Read: accumulate until CRLFCRLF or cap.  sd is still blocking here, so
     * each recv() is gated behind a bounded select() -- a peer that opens
     * the connection and sends nothing (or trickles bytes in past the first
     * segment) must not be able to hang this call, and with it the whole
     * single-threaded server, forever. */
    while (total < (int)sizeof(buf))
    {
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
            msg(D_LINK_ERRORS,
                "--sni-gateway-server sni-http-path-upgrade: timed out reading Upgrade request");
            return false;
        }
        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-gateway-server sni-http-path-upgrade: select() failed reading Upgrade request");
            return false;
        }

        ssize_t n = recv(sd, buf + total, (int)(sizeof(buf) - total), 0);
        if (n < 0)
        {
            int e = openvpn_errno();
            if (e == EINTR || e == EAGAIN || e == EWOULDBLOCK)
            {
                continue;
            }
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-gateway-server sni-http-path-upgrade: recv() reading Upgrade request");
            return false;
        }
        if (n == 0)
        {
            msg(D_LINK_ERRORS,
                "--sni-gateway-server sni-http-path-upgrade: connection closed before Upgrade request");
            return false;
        }
        total += (int)n;
        for (int i = 0; i + 4 <= total; i++)
        {
            if (buf[i] == '\r' && buf[i + 1] == '\n'
                && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            {
                end_pos = i + 4;
                break;
            }
        }
        if (end_pos >= 0)
        {
            break;
        }
    }

    if (end_pos < 0)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: Upgrade request too large or truncated");
        return false;
    }

    const char *data = buf;
    int len = end_pos;

    if (len < 4 || memcmp(data, "GET ", 4) != 0)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: not a GET request");
        return false;
    }

    const char *line_end = memchr(data, '\r', (size_t)len);
    if (!line_end)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: malformed request line");
        return false;
    }

    const char *path_start = data + 4;
    const char *sp = memchr(path_start, ' ', (size_t)(line_end - path_start));
    if (!sp || sp == path_start || path_start[0] != '/')
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: malformed request path");
        return false;
    }
    int path_len = (int)(sp - path_start);

    const char *ver = sp + 1;
    if ((int)(line_end - ver) != 8 || memcmp(ver, "HTTP/1.1", 8) != 0)
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: unsupported HTTP version");
        return false;
    }

    const char *hdrs = line_end + 2;
    int hdrs_len = (int)(data + len - hdrs);
    if (!http_has_upgrade_token(hdrs, hdrs_len, token))
    {
        msg(M_WARN, "--sni-gateway-server sni-http-path-upgrade: missing or mismatched "
                    "'Upgrade: %s' header",
            token);
        return false;
    }

    if (require_path)
    {
        int rp_len = (int)strlen(require_path);
        if (rp_len != path_len || memcmp(path_start, require_path, (size_t)path_len) != 0)
        {
            msg(M_WARN,
                "--sni-gateway-server sni-http-path-upgrade: path mismatch (expected '%s', got '%.*s')",
                require_path, path_len, path_start);
            return false;
        }
    }

    msg(M_INFO, "--sni-gateway-server sni-http-path-upgrade: accepted %d-byte Upgrade request (path '%.*s')",
        end_pos, path_len, path_start);

    return sni_gw_http_send_101(sd, token);
}
