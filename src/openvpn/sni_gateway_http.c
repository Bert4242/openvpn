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

/*
 * Upper bound on the HTTP Upgrade request we are willing to buffer before the
 * terminating blank line.  The genuine request is well under 200 bytes; this
 * cap just stops a misbehaving/hostile peer from making us buffer forever.
 */
#define SNI_GW_HTTP_MAX_REQUEST 4096

/* ------------------------------------------------------------------------- */
/* Fixed response bytes                                                       */
/* ------------------------------------------------------------------------- */

const char sni_gw_http_101_response[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: " SNI_GW_HTTP_UPGRADE_TOKEN "\r\n"
    "\r\n";

size_t
sni_gw_http_101_response_len(void)
{
    return sizeof(sni_gw_http_101_response) - 1; /* exclude the NUL */
}

/* ------------------------------------------------------------------------- */
/* Client request builder                                                     */
/* ------------------------------------------------------------------------- */

size_t
sni_gw_http_build_upgrade(char *buf, size_t bufsz, const char *host, const char *path)
{
    if (!buf || bufsz == 0 || !host || !*host || !path || path[0] != '/')
    {
        return 0;
    }

    int n = snprintf(buf, bufsz,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: Upgrade\r\n"
                     "Upgrade: " SNI_GW_HTTP_UPGRADE_TOKEN "\r\n"
                     "\r\n",
                     path, host);
    if (n < 0 || (size_t)n >= bufsz)
    {
        return 0; /* encoding error or truncated -> overflow */
    }
    return (size_t)n;
}

/* ------------------------------------------------------------------------- */
/* Server request parser                                                      */
/* ------------------------------------------------------------------------- */

/* Case-insensitive substring search over a bounded (non-NUL-terminated) span. */
static bool
mem_casefind(const char *hay, int haylen, const char *needle)
{
    int nlen = (int)strlen(needle);
    if (nlen == 0)
    {
        return true;
    }
    for (int i = 0; i + nlen <= haylen; i++)
    {
        if (strncasecmp(hay + i, needle, (size_t)nlen) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
 * Scan the header block [hdrs, hdrs+hdrs_len) (which starts right after the
 * request line and ends at the final blank line) for a header line
 *   Upgrade: ... openvpn ...
 * with a case-insensitive name and a value that contains the openvpn token.
 */
static bool
http_has_upgrade_openvpn(const char *hdrs, int hdrs_len)
{
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
                int vlen = (int)(eol - v);
                if (mem_casefind(v, vlen, SNI_GW_HTTP_UPGRADE_TOKEN))
                {
                    return true;
                }
            }
        }

        p = eol + 2; /* skip the CRLF (safe: memchr found '\r' before stop) */
    }
    return false;
}

int
sni_gw_http_check_and_consume_request(struct stream_buf *sb, const char *require_path)
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
            msg(M_INFO, "--sni-gateway-server http: non-HTTP client, proceeding as OpenVPN");
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
            msg(M_WARN, "--sni-gateway-server http: request header exceeds %d bytes, rejecting",
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
        goto reject; /* cannot happen (CRLFCRLF found) but be defensive */
    }
    const char *path_start = data + 4; /* just past "GET " */
    const char *sp = memchr(path_start, ' ', (size_t)(line_end - path_start));
    if (!sp || sp == path_start)
    {
        msg(M_WARN, "--sni-gateway-server http: malformed request line, rejecting");
        goto reject;
    }
    int path_len = (int)(sp - path_start);
    if (path_start[0] != '/')
    {
        msg(M_WARN, "--sni-gateway-server http: request path does not start with '/', rejecting");
        goto reject;
    }

    /* Version token must be exactly "HTTP/1.1". */
    const char *ver = sp + 1;
    int ver_len = (int)(line_end - ver);
    if (ver_len != 8 || memcmp(ver, "HTTP/1.1", 8) != 0)
    {
        msg(M_WARN, "--sni-gateway-server http: unsupported HTTP version, rejecting");
        goto reject;
    }

    /* Require the Upgrade: openvpn header. */
    const char *hdrs = line_end + 2; /* past the request line's CRLF */
    int hdrs_len = (int)(end - hdrs);
    if (!http_has_upgrade_openvpn(hdrs, hdrs_len))
    {
        msg(M_WARN, "--sni-gateway-server http: missing 'Upgrade: openvpn' header, rejecting");
        goto reject;
    }

    /* Optional exact path enforcement. */
    if (require_path)
    {
        int rp_len = (int)strlen(require_path);
        if (rp_len != path_len || memcmp(path_start, require_path, (size_t)path_len) != 0)
        {
            msg(M_WARN, "--sni-gateway-server http: request path does not match "
                        "--sni-gateway-server-path, rejecting");
            goto reject;
        }
    }

    /* Success: strip the consumed request, leaving any trailing OpenVPN bytes. */
    {
        int remaining = len - request_len;
        msg(M_INFO, "--sni-gateway-server http: consumed %d-byte Upgrade request (path '%.*s')",
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
sni_gw_http_send_101(socket_descriptor_t sd)
{
    const char *p = sni_gw_http_101_response;
    size_t total = sni_gw_http_101_response_len();
    size_t sent = 0;
    int attempts = 0;

    while (sent < total)
    {
        ssize_t s = send(sd, p + sent, total - sent, MSG_NOSIGNAL);
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
                msg(D_LINK_ERRORS, "--sni-gateway-server http: timed out sending 101 response");
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

        msg(D_LINK_ERRORS | M_ERRNO, "--sni-gateway-server http: send() of 101 response failed");
        return false;
    }
    return true;
}

bool
sni_gw_http_server_accept_upgrade(socket_descriptor_t sd, const char *require_path)
{
    char buf[SNI_GW_HTTP_MAX_REQUEST];
    int total = 0;
    int end_pos = -1; /* byte offset just past the CRLFCRLF terminator */

    /* Blocking read: accumulate until CRLFCRLF or cap. */
    while (total < (int)sizeof(buf))
    {
        ssize_t n = recv(sd, buf + total, (size_t)(sizeof(buf) - total), 0);
        if (n < 0)
        {
            if (openvpn_errno() == EINTR)
            {
                continue;
            }
            msg(D_LINK_ERRORS | M_ERRNO,
                "--sni-gateway-server http: recv() reading Upgrade request");
            return false;
        }
        if (n == 0)
        {
            msg(D_LINK_ERRORS,
                "--sni-gateway-server http: connection closed before Upgrade request");
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
        msg(M_WARN, "--sni-gateway-server http: Upgrade request too large or truncated");
        return false;
    }

    const char *data = buf;
    int len = end_pos;

    if (len < 4 || memcmp(data, "GET ", 4) != 0)
    {
        msg(M_WARN, "--sni-gateway-server http: not a GET request");
        return false;
    }

    const char *line_end = memchr(data, '\r', (size_t)len);
    if (!line_end)
    {
        msg(M_WARN, "--sni-gateway-server http: malformed request line");
        return false;
    }

    const char *path_start = data + 4;
    const char *sp = memchr(path_start, ' ', (size_t)(line_end - path_start));
    if (!sp || sp == path_start || path_start[0] != '/')
    {
        msg(M_WARN, "--sni-gateway-server http: malformed request path");
        return false;
    }
    int path_len = (int)(sp - path_start);

    const char *ver = sp + 1;
    if ((int)(line_end - ver) != 8 || memcmp(ver, "HTTP/1.1", 8) != 0)
    {
        msg(M_WARN, "--sni-gateway-server http: unsupported HTTP version");
        return false;
    }

    const char *hdrs = line_end + 2;
    int hdrs_len = (int)(data + len - hdrs);
    if (!http_has_upgrade_openvpn(hdrs, hdrs_len))
    {
        msg(M_WARN, "--sni-gateway-server http: missing 'Upgrade: openvpn' header");
        return false;
    }

    if (require_path)
    {
        int rp_len = (int)strlen(require_path);
        if (rp_len != path_len || memcmp(path_start, require_path, (size_t)path_len) != 0)
        {
            msg(M_WARN,
                "--sni-gateway-server http: path mismatch (expected '%s', got '%.*s')",
                require_path, path_len, path_start);
            return false;
        }
    }

    msg(M_INFO, "--sni-gateway-server http: accepted %d-byte Upgrade request (path '%.*s')",
        end_pos, path_len, path_start);

    return sni_gw_http_send_101(sd);
}
