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

/*
 * Unit tests for the transport-independent pieces of
 * --sni-gateway sni-tls-http-path-upgrade, plus the plain-socket
 * --sni-gateway sni-http-path-upgrade client-side upgrade:
 *   - sni_gw_http_build_upgrade()             (client request builder)
 *   - sni_gw_http_build_101()                 (server response builder)
 *   - sni_gw_http_check_and_consume_request() (server request state machine)
 *   - sni_gw_http_client_read_101()           (shared client response reader)
 *   - sni_gw_http_client_upgrade_plain()      (plain-socket client upgrade)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include <sys/socket.h>
#include <unistd.h>

#include "buffer.h"
#include "socket.h"
#include "sni_gateway_http.h"
#include "mock_msg.h"
#include "test_common.h"

/* stub for get_signal()'s dependency instead of pulling in all of sig.c --
 * same pattern as test_socket.c/test_ssl.c. */
struct signal_info siginfo_static; /* GLOBAL */

/* ==========================================================================
 * sni_gw_http_build_upgrade
 * ========================================================================== */

static void
test_build_upgrade_exact_bytes(void **state)
{
    (void)state;
    char buf[512];
    const char *expect =
        "GET /vpn HTTP/1.1\r\n"
        "Host: gw.example.com\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    size_t n = sni_gw_http_build_upgrade(buf, sizeof(buf), "gw.example.com", "/vpn", "openvpn");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
    /* NUL-terminated because bufsz > n. */
    assert_int_equal(buf[n], '\0');
}

static void
test_build_upgrade_root_path(void **state)
{
    (void)state;
    char buf[512];
    const char *expect =
        "GET / HTTP/1.1\r\n"
        "Host: h\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    size_t n = sni_gw_http_build_upgrade(buf, sizeof(buf), "h", "/", "openvpn");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
}

static void
test_build_upgrade_custom_token_exact_bytes(void **state)
{
    (void)state;
    char buf[512];
    const char *expect =
        "GET /vpn HTTP/1.1\r\n"
        "Host: gw.example.com\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "\r\n";
    size_t n = sni_gw_http_build_upgrade(buf, sizeof(buf), "gw.example.com", "/vpn", "websocket");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
}

static void
test_build_upgrade_overflow(void **state)
{
    (void)state;
    char small[16];
    assert_int_equal((int)sni_gw_http_build_upgrade(small, sizeof(small),
                                                    "gw.example.com", "/vpn", "openvpn"),
                     0);
    /* Exactly one byte too small (bufsz == request length -> no room for NUL). */
    char buf[512];
    size_t need = sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "/p", "openvpn");
    assert_true(need > 0);
    char tight[512];
    assert_int_equal((int)sni_gw_http_build_upgrade(tight, need, "host", "/p", "openvpn"), 0);
}

static void
test_build_upgrade_bad_path(void **state)
{
    (void)state;
    char buf[512];
    /* empty path */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "", "openvpn"), 0);
    /* path not starting with '/' */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "vpn", "openvpn"), 0);
    /* NULL path / host */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", NULL, "openvpn"), 0);
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), NULL, "/vpn", "openvpn"), 0);
    /* empty host */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "", "/vpn", "openvpn"), 0);
}

static void
test_build_upgrade_bad_token(void **state)
{
    (void)state;
    char buf[512];
    /* empty / NULL token -- build_upgrade only checks non-empty defensively
     * (the real charset/length validation happens once at options-parse
     * time via sni_gw_upgrade_token_is_valid()). */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "/vpn", ""), 0);
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "/vpn", NULL), 0);
}

/* ==========================================================================
 * sni_gw_http_build_101
 * ========================================================================== */

static void
test_build_101_default_token_exact_bytes(void **state)
{
    (void)state;
    char buf[256];
    const char *expect =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    size_t n = sni_gw_http_build_101(buf, sizeof(buf), "openvpn");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
}

static void
test_build_101_custom_token_exact_bytes(void **state)
{
    (void)state;
    char buf[256];
    const char *expect =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "\r\n";
    size_t n = sni_gw_http_build_101(buf, sizeof(buf), "websocket");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
}

static void
test_build_101_bad_token(void **state)
{
    (void)state;
    char buf[256];
    assert_int_equal((int)sni_gw_http_build_101(buf, sizeof(buf), ""), 0);
    assert_int_equal((int)sni_gw_http_build_101(buf, sizeof(buf), NULL), 0);
}

static void
test_build_101_overflow(void **state)
{
    (void)state;
    char small[8];
    assert_int_equal((int)sni_gw_http_build_101(small, sizeof(small), "openvpn"), 0);
}

/* ==========================================================================
 * sni_gw_http_check_and_consume_request
 * ========================================================================== */

/* Build a stream_buf whose sb->buf holds len bytes of data, in PENDING state. */
static void
make_http_sb(struct stream_buf *sb, const void *data, int len)
{
    memset(sb, 0, sizeof(*sb));
    sb->buf = alloc_buf((size_t)len + 64);
    sb->maxlen = (int)BCAP(&sb->buf);
    assert_true(buf_write(&sb->buf, data, (size_t)len));
    sb->sni_gw_http_state = SNI_GW_HTTP_PENDING;
}

static void
free_http_sb(struct stream_buf *sb)
{
    free_buf(&sb->buf);
}

static const char valid_req[] =
    "GET /vpn HTTP/1.1\r\n"
    "Host: gw.example.com\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: openvpn\r\n"
    "\r\n";

static void
test_consume_valid(void **state)
{
    (void)state;
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));

    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, (int)strlen(valid_req));
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    assert_false(sb.error);
    assert_int_equal(sb.buf.len, 0); /* whole request consumed, nothing trailing */
    free_http_sb(&sb);
}

static void
test_consume_valid_with_trailing_openvpn(void **state)
{
    (void)state;
    const uint8_t trailer[] = { 0x00, 0x2a, 0x38, 0x01, 0x02, 0x03 };
    int reqlen = (int)strlen(valid_req);
    uint8_t combined[sizeof(valid_req) + sizeof(trailer)];
    memcpy(combined, valid_req, reqlen);
    memcpy(combined + reqlen, trailer, sizeof(trailer));

    struct stream_buf sb;
    make_http_sb(&sb, combined, reqlen + (int)sizeof(trailer));

    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, reqlen);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    /* trailing OpenVPN bytes remain, moved to the front of sb->buf */
    assert_int_equal(sb.buf.len, (int)sizeof(trailer));
    assert_memory_equal(BPTR(&sb.buf), trailer, sizeof(trailer));
    free_http_sb(&sb);
}

static void
test_consume_partial_need_more(void **state)
{
    (void)state;
    /* Everything but the final blank line. */
    const char partial[] =
        "GET /vpn HTTP/1.1\r\n"
        "Host: gw.example.com\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, partial, (int)strlen(partial));

    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, 0); /* need more */
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_PENDING);
    assert_false(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_partial_get_prefix(void **state)
{
    (void)state;
    /* Only "GE" so far: matches the GET prefix, need more. */
    struct stream_buf sb;
    make_http_sb(&sb, "GE", 2);
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, 0);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_PENDING);
    free_http_sb(&sb);
}

static void
test_consume_raw_openvpn(void **state)
{
    (void)state;
    /* Binary OpenVPN-ish first bytes: not "GET " -> disable, proceed normally. */
    const uint8_t raw[] = { 0x00, 0x2a, 0x38, 0x01 };
    struct stream_buf sb;
    make_http_sb(&sb, raw, (int)sizeof(raw));

    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, -1);
    assert_false(sb.error); /* NOT an error: just a plain OpenVPN client */
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_DISABLED);
    /* buffer untouched */
    assert_int_equal(sb.buf.len, (int)sizeof(raw));
    free_http_sb(&sb);
}

static void
test_consume_wrong_method(void **state)
{
    (void)state;
    const char req[] =
        "POST /vpn HTTP/1.1\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, req, (int)strlen(req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    /* "POST" fails the "GET " prefix at byte 3 -> treated as raw (not error). */
    assert_int_equal(r, -1);
    assert_false(sb.error);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_DISABLED);
    free_http_sb(&sb);
}

static void
test_consume_missing_upgrade(void **state)
{
    (void)state;
    const char req[] =
        "GET /vpn HTTP/1.1\r\n"
        "Host: gw.example.com\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, req, (int)strlen(req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error); /* rejected */
    free_http_sb(&sb);
}

static void
test_consume_bad_version(void **state)
{
    (void)state;
    const char req[] =
        "GET /vpn HTTP/1.0\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, req, (int)strlen(req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_bad_path_no_slash(void **state)
{
    (void)state;
    /* "GET " prefix matches, but the target does not start with '/'. */
    const char req[] =
        "GET vpn HTTP/1.1\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, req, (int)strlen(req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_oversized(void **state)
{
    (void)state;
    /* A "GET " request with no terminating blank line, larger than the cap. */
    int big = 5000;
    char *data = malloc((size_t)big);
    assert_non_null(data);
    memcpy(data, "GET /", 5);
    memset(data + 5, 'a', (size_t)(big - 5));

    struct stream_buf sb;
    make_http_sb(&sb, data, big);
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
    free(data);
}

static void
test_consume_require_path_match(void **state)
{
    (void)state;
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));
    int r = sni_gw_http_check_and_consume_request(&sb, "/vpn", "openvpn");
    assert_int_equal(r, (int)strlen(valid_req));
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    assert_false(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_require_path_mismatch(void **state)
{
    (void)state;
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));
    int r = sni_gw_http_check_and_consume_request(&sb, "/other", "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_require_path_prefix_mismatch(void **state)
{
    (void)state;
    /* require_path is a prefix of the request path: must NOT match (exact). */
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));
    int r = sni_gw_http_check_and_consume_request(&sb, "/vp", "openvpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

/* ==========================================================================
 * sni_gw_http_check_and_consume_request -- Upgrade token matching
 * ========================================================================== */

static void
test_consume_upgrade_token_mismatch(void **state)
{
    (void)state;
    /* Request advertises "openvpn"; server configured for a different token. */
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "websocket");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_upgrade_token_substring_no_longer_matches(void **state)
{
    (void)state;
    /* Under the OLD substring-search behavior, a configured token of "vpn"
     * would have matched the "openvpn" header value. Exact (comma-split,
     * trimmed) matching must now reject this. */
    struct stream_buf sb;
    make_http_sb(&sb, valid_req, (int)strlen(valid_req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "vpn");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

static void
test_consume_upgrade_token_comma_list_match(void **state)
{
    (void)state;
    const char req[] =
        "GET /vpn HTTP/1.1\r\n"
        "Host: gw.example.com\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: foo, openvpn, bar\r\n"
        "\r\n";
    struct stream_buf sb;
    make_http_sb(&sb, req, (int)strlen(req));
    int r = sni_gw_http_check_and_consume_request(&sb, NULL, "openvpn");
    assert_int_equal(r, (int)strlen(req));
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    assert_false(sb.error);
    free_http_sb(&sb);
}

/* Round-trip: the exact bytes the client builder produces are accepted by the
 * server consumer. */
static void
test_build_then_consume_roundtrip(void **state)
{
    (void)state;
    char req[512];
    size_t n = sni_gw_http_build_upgrade(req, sizeof(req), "gw.example.com", "/tunnel", "openvpn");
    assert_true(n > 0);

    struct stream_buf sb;
    make_http_sb(&sb, req, (int)n);
    int r = sni_gw_http_check_and_consume_request(&sb, "/tunnel", "openvpn");
    assert_int_equal(r, (int)n);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    free_http_sb(&sb);
}

static void
test_build_then_consume_roundtrip_custom_token(void **state)
{
    (void)state;
    char req[512];
    size_t n = sni_gw_http_build_upgrade(req, sizeof(req), "gw.example.com", "/tunnel", "websocket");
    assert_true(n > 0);

    struct stream_buf sb;
    make_http_sb(&sb, req, (int)n);
    int r = sni_gw_http_check_and_consume_request(&sb, "/tunnel", "websocket");
    assert_int_equal(r, (int)n);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    free_http_sb(&sb);
}

/* ==========================================================================
 * sni_gw_http_client_read_101 -- via an in-memory callback (no socket)
 * ========================================================================== */

struct mem_read_ctx
{
    const uint8_t *data;
    int len;
    int pos;
};

static bool
mem_read_byte(void *ctx, uint8_t *out, volatile int *signal_received, int poll_timeout)
{
    (void)signal_received;
    (void)poll_timeout;
    struct mem_read_ctx *m = (struct mem_read_ctx *)ctx;
    if (m->pos >= m->len)
    {
        return false; /* out of bytes -- same as a closed/exhausted transport */
    }
    *out = m->data[m->pos++];
    return true;
}

static void
test_client_read_101_valid(void **state)
{
    (void)state;
    const char resp[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    struct mem_read_ctx ctx = { .data = (const uint8_t *)resp, .len = (int)strlen(resp), .pos = 0 };
    volatile int sig = 0;
    assert_true(sni_gw_http_client_read_101(mem_read_byte, &ctx, &sig, 5, "test"));
}

static void
test_client_read_101_bad_status(void **state)
{
    (void)state;
    const char resp[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    struct mem_read_ctx ctx = { .data = (const uint8_t *)resp, .len = (int)strlen(resp), .pos = 0 };
    volatile int sig = 0;
    assert_false(sni_gw_http_client_read_101(mem_read_byte, &ctx, &sig, 5, "test"));
}

static void
test_client_read_101_never_terminated(void **state)
{
    (void)state;
    /* Runs out of bytes (mem_read_byte returns false) before CRLFCRLF. */
    const char resp[] = "HTTP/1.1 101 Switching Protocols\r\n";
    struct mem_read_ctx ctx = { .data = (const uint8_t *)resp, .len = (int)strlen(resp), .pos = 0 };
    volatile int sig = 0;
    assert_false(sni_gw_http_client_read_101(mem_read_byte, &ctx, &sig, 5, "test"));
}

/* ==========================================================================
 * sni_gw_http_client_upgrade_plain -- over a real loopback socket
 * ========================================================================== */

static void
test_client_upgrade_plain_success(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    /* Pre-write the canned "gateway" response to fds[1] -- it sits in the
     * kernel's fds[0]-readable queue regardless of write/read ordering, so
     * this stays single-threaded (no fork/pthread needed). */
    const char resp[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: openvpn\r\n"
        "\r\n";
    assert_int_equal(send(fds[1], resp, strlen(resp), 0), (ssize_t)strlen(resp));

    volatile int sig = 0;
    assert_true(sni_gw_http_client_upgrade_plain(fds[0], "gw.example.com", "/vpn", "openvpn", &sig, 5));

    /* The request bytes sent must match the builder's output exactly. */
    char req[512];
    size_t n = sni_gw_http_build_upgrade(req, sizeof(req), "gw.example.com", "/vpn", "openvpn");
    char got[512];
    ssize_t r = recv(fds[1], got, sizeof(got), 0);
    assert_true(r > 0);
    assert_int_equal((size_t)r, n);
    assert_memory_equal(got, req, n);

    close(fds[0]);
    close(fds[1]);
}

static void
test_client_upgrade_plain_custom_token_roundtrip(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    /* Server-side response built via sni_gw_http_build_101() with a custom
     * token, proving the new dynamic-length response works over the wire
     * (not just via direct byte-comparison in isolation). */
    char resp[256];
    size_t resplen = sni_gw_http_build_101(resp, sizeof(resp), "websocket");
    assert_true(resplen > 0);
    assert_int_equal(send(fds[1], resp, resplen, 0), (ssize_t)resplen);

    volatile int sig = 0;
    assert_true(sni_gw_http_client_upgrade_plain(fds[0], "gw.example.com", "/vpn",
                                                 "websocket", &sig, 5));

    char req[512];
    size_t n = sni_gw_http_build_upgrade(req, sizeof(req), "gw.example.com", "/vpn", "websocket");
    char got[512];
    ssize_t r = recv(fds[1], got, sizeof(got), 0);
    assert_true(r > 0);
    assert_int_equal((size_t)r, n);
    assert_memory_equal(got, req, n);

    close(fds[0]);
    close(fds[1]);
}

static void
test_client_upgrade_plain_bad_status_line(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const char resp[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    assert_int_equal(send(fds[1], resp, strlen(resp), 0), (ssize_t)strlen(resp));

    volatile int sig = 0;
    assert_false(sni_gw_http_client_upgrade_plain(fds[0], "gw.example.com", "/vpn", "openvpn", &sig, 5));

    close(fds[0]);
    close(fds[1]);
}

static void
test_client_upgrade_plain_connection_closed_mid_response(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const char partial[] = "HTTP/1.1 101 Swi";
    assert_int_equal(send(fds[1], partial, strlen(partial), 0), (ssize_t)strlen(partial));
    close(fds[1]); /* peer closes before the response completes */

    volatile int sig = 0;
    assert_false(sni_gw_http_client_upgrade_plain(fds[0], "gw.example.com", "/vpn", "openvpn", &sig, 5));

    close(fds[0]);
}

static void
test_client_upgrade_plain_oversized_header(void **state)
{
    (void)state;
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    /* > 1024 bytes, no CRLFCRLF anywhere -- the reader must give up at its
     * 1024-byte cap rather than block forever. */
    char big[1200];
    memset(big, 'a', sizeof(big));
    size_t off = 0;
    while (off < sizeof(big))
    {
        ssize_t s = send(fds[1], big + off, sizeof(big) - off, 0);
        assert_true(s > 0);
        off += (size_t)s;
    }

    volatile int sig = 0;
    assert_false(sni_gw_http_client_upgrade_plain(fds[0], "gw.example.com", "/vpn", "openvpn", &sig, 5));

    close(fds[0]);
    close(fds[1]);
}

static void
test_client_upgrade_plain_bad_host_or_path(void **state)
{
    (void)state;
    volatile int sig = 0;
    /* Fails building the request before ever touching the socket -- sd=-1
     * is safe here since it must never be used. */
    assert_false(sni_gw_http_client_upgrade_plain(-1, "gw.example.com", "vpn" /* no leading '/' */,
                                                  "openvpn", &sig, 5));
    assert_false(sni_gw_http_client_upgrade_plain(-1, NULL, "/vpn", "openvpn", &sig, 5));
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        /* build_upgrade */
        cmocka_unit_test(test_build_upgrade_exact_bytes),
        cmocka_unit_test(test_build_upgrade_root_path),
        cmocka_unit_test(test_build_upgrade_custom_token_exact_bytes),
        cmocka_unit_test(test_build_upgrade_overflow),
        cmocka_unit_test(test_build_upgrade_bad_path),
        cmocka_unit_test(test_build_upgrade_bad_token),

        /* build_101 */
        cmocka_unit_test(test_build_101_default_token_exact_bytes),
        cmocka_unit_test(test_build_101_custom_token_exact_bytes),
        cmocka_unit_test(test_build_101_bad_token),
        cmocka_unit_test(test_build_101_overflow),

        /* check_and_consume_request */
        cmocka_unit_test(test_consume_valid),
        cmocka_unit_test(test_consume_valid_with_trailing_openvpn),
        cmocka_unit_test(test_consume_partial_need_more),
        cmocka_unit_test(test_consume_partial_get_prefix),
        cmocka_unit_test(test_consume_raw_openvpn),
        cmocka_unit_test(test_consume_wrong_method),
        cmocka_unit_test(test_consume_missing_upgrade),
        cmocka_unit_test(test_consume_bad_version),
        cmocka_unit_test(test_consume_bad_path_no_slash),
        cmocka_unit_test(test_consume_oversized),
        cmocka_unit_test(test_consume_require_path_match),
        cmocka_unit_test(test_consume_require_path_mismatch),
        cmocka_unit_test(test_consume_require_path_prefix_mismatch),
        cmocka_unit_test(test_consume_upgrade_token_mismatch),
        cmocka_unit_test(test_consume_upgrade_token_substring_no_longer_matches),
        cmocka_unit_test(test_consume_upgrade_token_comma_list_match),
        cmocka_unit_test(test_build_then_consume_roundtrip),
        cmocka_unit_test(test_build_then_consume_roundtrip_custom_token),

        /* sni_gw_http_client_read_101 (in-memory) */
        cmocka_unit_test(test_client_read_101_valid),
        cmocka_unit_test(test_client_read_101_bad_status),
        cmocka_unit_test(test_client_read_101_never_terminated),

        /* sni_gw_http_client_upgrade_plain (loopback socket) */
        cmocka_unit_test(test_client_upgrade_plain_success),
        cmocka_unit_test(test_client_upgrade_plain_bad_status_line),
        cmocka_unit_test(test_client_upgrade_plain_connection_closed_mid_response),
        cmocka_unit_test(test_client_upgrade_plain_oversized_header),
        cmocka_unit_test(test_client_upgrade_plain_bad_host_or_path),
        cmocka_unit_test(test_client_upgrade_plain_custom_token_roundtrip),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
