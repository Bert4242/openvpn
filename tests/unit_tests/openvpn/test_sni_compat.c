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
 * Cross-path compatibility test for the SNI passthrough builder and checker.
 *
 * sni_compat_testdriver links two separately-compiled translations of
 * ps_sni.c into the same binary:
 *
 *   ps_sni.c        – compiled normally (OpenSSL path on OpenSSL builds,
 *                     generic path on LibreSSL / mbedTLS / …).
 *   sni_alt_impl.c  – compiled with SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH
 *                     forced, all public symbols renamed with an "_alt"
 *                     suffix to avoid linker conflicts.
 *
 * The four builder × checker combinations tested here:
 *
 *   normal  builder  × normal  checker   (1)
 *   normal  builder  × alt     checker   (2)  ← key: LibreSSL parses OpenSSL hello
 *   alt     builder  × normal  checker   (3)  ← key: OpenSSL parses template hello
 *   alt     builder  × alt     checker   (4)
 *
 * Each combination is run with a short SNI (shorter than the 21-byte
 * template reference) and a long SNI (longer, exercising the length-patch
 * logic in the alt builder).
 *
 * On non-OpenSSL builds (LibreSSL, mbedTLS, …) the "normal" and "alt"
 * symbols both resolve to the generic byte-scan code; all eight tests
 * still pass and confirm that the generic path is self-consistent.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"


#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <stddef.h>

#include "buffer.h"
#include "socket.h"
#include "ps_sni.h" /* declares sni_passthrough_build_client_hello_test,
                          * sni_passthrough_check_and_consume_header         */
#include "mock_msg.h"
#include "test_common.h"

/* -------------------------------------------------------------------------
 * Symbols from sni_alt_impl.c (always the generic byte-scan path).
 * ------------------------------------------------------------------------- */
size_t sni_passthrough_build_client_hello_alt_test_path_wrapper(uint8_t *buf,
                                                                size_t bufsz,
                                                                const char *sni,
                                                                const char *const *alpn_list,
                                                                int alpn_count);
bool sni_passthrough_check_and_consume_header_alt_test_path(
    struct stream_buf *sb,
    const struct sni_pt_server_check_ctx *ctx);

/* -------------------------------------------------------------------------
 * SNI hostnames used across the test matrix.
 *
 * SHORT_SNI is 15 bytes (< 21-byte template reference).
 * LONG_SNI  is 41 bytes (> 21-byte template reference) to exercise the
 * length-patch arithmetic inside the alt builder.
 * ------------------------------------------------------------------------- */
#define SHORT_SNI "vpn.example.com"
#define LONG_SNI  "vpn.this-is-a-longer-hostname.example.com"

/* -------------------------------------------------------------------------
 * Helper types and functions.
 * ------------------------------------------------------------------------- */
typedef size_t (*builder_fn)(uint8_t *, size_t, const char *,
                             const char *const *, int);
typedef bool (*checker_fn)(struct stream_buf *,
                           const struct sni_pt_server_check_ctx *);

static void
make_stream_buf(struct stream_buf *sb, const uint8_t *data, int len)
{
    memset(sb, 0, sizeof(*sb));
    sb->buf = alloc_buf((size_t)len + 16);
    assert_true(buf_write(&sb->buf, data, (size_t)len));
    sb->sni_passthrough_state = SNI_PT_PENDING;
}

static void
free_stream_buf(struct stream_buf *sb)
{
    free_buf(&sb->buf);
}

/*
 * run_compat_test – build a ClientHello with <build>, feed it to <check>,
 * and assert that the header is consumed and the state transitions to
 * SNI_PT_SUCCESS.
 * Uses the built-in default ALPN token and no hostname filter.
 */
static void
run_compat_test(builder_fn build, checker_fn check, const char *sni)
{
    uint8_t buf[4096];
    size_t len = build(buf, sizeof(buf), sni, NULL, 0);
    assert_true(len > 0);

    struct stream_buf sb;
    make_stream_buf(&sb, buf, (int)len);

    /* Default ctx: use built-in ALPN, accept any hostname */
    const struct sni_pt_server_check_ctx ctx = { 0 };
    bool result = check(&sb, &ctx);

    assert_true(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_SUCCESS);
    assert_int_equal(sb.buf.len, 0); /* entire header consumed, nothing trailing */

    free_stream_buf(&sb);
}

/* -------------------------------------------------------------------------
 * Test cases – short SNI
 * ------------------------------------------------------------------------- */

static void
test_compat_normal_build_normal_check(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_test,
                    sni_passthrough_check_and_consume_header,
                    SHORT_SNI);
}

static void
test_compat_normal_build_alt_check(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_test,
                    sni_passthrough_check_and_consume_header_alt_test_path,
                    SHORT_SNI);
}

static void
test_compat_alt_build_normal_check(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_alt_test_path_wrapper,
                    sni_passthrough_check_and_consume_header,
                    SHORT_SNI);
}

static void
test_compat_alt_build_alt_check(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_alt_test_path_wrapper,
                    sni_passthrough_check_and_consume_header_alt_test_path,
                    SHORT_SNI);
}

/* -------------------------------------------------------------------------
 * Test cases – long SNI (exercises alt builder length-patch arithmetic)
 * ------------------------------------------------------------------------- */

static void
test_compat_normal_build_normal_check_long_sni(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_test,
                    sni_passthrough_check_and_consume_header,
                    LONG_SNI);
}

static void
test_compat_normal_build_alt_check_long_sni(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_test,
                    sni_passthrough_check_and_consume_header_alt_test_path,
                    LONG_SNI);
}

static void
test_compat_alt_build_normal_check_long_sni(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_alt_test_path_wrapper,
                    sni_passthrough_check_and_consume_header,
                    LONG_SNI);
}

static void
test_compat_alt_build_alt_check_long_sni(void **state)
{
    (void)state;
    run_compat_test(sni_passthrough_build_client_hello_alt_test_path_wrapper,
                    sni_passthrough_check_and_consume_header_alt_test_path,
                    LONG_SNI);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------------- */

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        /* Short SNI */
        cmocka_unit_test(test_compat_normal_build_normal_check),
        cmocka_unit_test(test_compat_normal_build_alt_check),
        cmocka_unit_test(test_compat_alt_build_normal_check),
        cmocka_unit_test(test_compat_alt_build_alt_check),
        /* Long SNI */
        cmocka_unit_test(test_compat_normal_build_normal_check_long_sni),
        cmocka_unit_test(test_compat_normal_build_alt_check_long_sni),
        cmocka_unit_test(test_compat_alt_build_normal_check_long_sni),
        cmocka_unit_test(test_compat_alt_build_alt_check_long_sni),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
