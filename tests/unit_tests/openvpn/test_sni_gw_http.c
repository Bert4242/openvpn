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
 * --sni-gateway sni-tls-http-path-upgrade:
 *   - sni_gw_http_build_upgrade()             (client request builder)
 *   - sni_gw_http_check_and_consume_request() (server request state machine)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include "buffer.h"
#include "socket.h"
#include "sni_gateway_http.h"
#include "mock_msg.h"
#include "test_common.h"

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
    size_t n = sni_gw_http_build_upgrade(buf, sizeof(buf), "gw.example.com", "/vpn");
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
    size_t n = sni_gw_http_build_upgrade(buf, sizeof(buf), "h", "/");
    assert_int_equal((int)n, (int)strlen(expect));
    assert_memory_equal(buf, expect, n);
}

static void
test_build_upgrade_overflow(void **state)
{
    (void)state;
    char small[16];
    assert_int_equal((int)sni_gw_http_build_upgrade(small, sizeof(small),
                                                    "gw.example.com", "/vpn"),
                     0);
    /* Exactly one byte too small (bufsz == request length -> no room for NUL). */
    char buf[512];
    size_t need = sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "/p");
    assert_true(need > 0);
    char tight[512];
    assert_int_equal((int)sni_gw_http_build_upgrade(tight, need, "host", "/p"), 0);
}

static void
test_build_upgrade_bad_path(void **state)
{
    (void)state;
    char buf[512];
    /* empty path */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", ""), 0);
    /* path not starting with '/' */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", "vpn"), 0);
    /* NULL path / host */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "host", NULL), 0);
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), NULL, "/vpn"), 0);
    /* empty host */
    assert_int_equal((int)sni_gw_http_build_upgrade(buf, sizeof(buf), "", "/vpn"), 0);
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

    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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

    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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

    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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

    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, NULL);
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
    int r = sni_gw_http_check_and_consume_request(&sb, "/vpn");
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
    int r = sni_gw_http_check_and_consume_request(&sb, "/other");
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
    int r = sni_gw_http_check_and_consume_request(&sb, "/vp");
    assert_int_equal(r, -1);
    assert_true(sb.error);
    free_http_sb(&sb);
}

/* Round-trip: the exact bytes the client builder produces are accepted by the
 * server consumer. */
static void
test_build_then_consume_roundtrip(void **state)
{
    (void)state;
    char req[512];
    size_t n = sni_gw_http_build_upgrade(req, sizeof(req), "gw.example.com", "/tunnel");
    assert_true(n > 0);

    struct stream_buf sb;
    make_http_sb(&sb, req, (int)n);
    int r = sni_gw_http_check_and_consume_request(&sb, "/tunnel");
    assert_int_equal(r, (int)n);
    assert_int_equal(sb.sni_gw_http_state, SNI_GW_HTTP_SUCCESS);
    free_http_sb(&sb);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        /* build_upgrade */
        cmocka_unit_test(test_build_upgrade_exact_bytes),
        cmocka_unit_test(test_build_upgrade_root_path),
        cmocka_unit_test(test_build_upgrade_overflow),
        cmocka_unit_test(test_build_upgrade_bad_path),

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
        cmocka_unit_test(test_build_then_consume_roundtrip),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
