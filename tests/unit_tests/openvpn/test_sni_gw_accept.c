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
 * Unit tests for the pure --sni-gateway-server auto accept-time
 * classifier: sni_gw_accept_classify_bytes().
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "socket.h"
#include "sig.h"
#include "sni_gateway_accept.h"
#include "mock_msg.h"
#include "test_common.h"

/* stub for get_signal()'s dependency instead of pulling in all of sig.c --
 * same pattern as test_sni_gw_http.c/test_socket.c/test_ssl.c. */
struct signal_info siginfo_static; /* GLOBAL */

static void
test_classify_sni_decoy_one_byte(void **state)
{
    (void)state;
    const uint8_t peek[] = { 0x16 };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, 1), SNI_GW_ACCEPT_SNI);
}

static void
test_classify_sni_decoy_full_record_header(void **state)
{
    (void)state;
    const uint8_t peek[] = { 0x16, 0x03, 0x01, 0x00 };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, sizeof(peek)), SNI_GW_ACCEPT_SNI);
}

static void
test_classify_http_get_full(void **state)
{
    (void)state;
    const uint8_t peek[] = { 'G', 'E', 'T', ' ' };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, sizeof(peek)), SNI_GW_ACCEPT_HTTP);
}

static void
test_classify_http_get_partial(void **state)
{
    (void)state;
    const uint8_t peek[] = { 'G', 'E' };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, sizeof(peek)), SNI_GW_ACCEPT_NEED_MORE);
}

static void
test_classify_plain_openvpn_prefix(void **state)
{
    (void)state;
    /* Same fixture as test_sni_gw_http.c's test_consume_raw_openvpn: a
     * realistic OpenVPN TCP length-prefix + opcode byte, not "GET " and
     * not 0x16. */
    const uint8_t peek[] = { 0x00, 0x2a, 0x38, 0x01 };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, sizeof(peek)), SNI_GW_ACCEPT_OTHER);
}

static void
test_classify_diverges_early(void **state)
{
    (void)state;
    /* First byte matches 'G', second byte does not match 'E' -> decided as
     * OTHER as soon as it diverges, without needing 4 bytes. */
    const uint8_t peek[] = { 'G', 'X' };
    assert_int_equal(sni_gw_accept_classify_bytes(peek, sizeof(peek)), SNI_GW_ACCEPT_OTHER);
}

static void
test_classify_g_prefix_length_byte_edge_case(void **state)
{
    (void)state;
    /* 'G' == 0x47: an OpenVPN packet-size high byte of 0x47 (a >18KB
     * declared length, far beyond any realistic tun-mtu/link-mtu) would
     * make byte 0 collide with "GET "'s first byte.  This only costs a few
     * bytes of classification latency (NEED_MORE) until it diverges --
     * never a misclassification, since real OpenVPN length-prefix bytes
     * essentially never spell out "GET " for four bytes running. */
    const uint8_t partial[] = { 0x47 };
    assert_int_equal(sni_gw_accept_classify_bytes(partial, sizeof(partial)),
                     SNI_GW_ACCEPT_NEED_MORE);

    const uint8_t diverges[] = { 0x47, 0x00, 0x38 };
    assert_int_equal(sni_gw_accept_classify_bytes(diverges, sizeof(diverges)),
                     SNI_GW_ACCEPT_OTHER);
}

static void
test_classify_need_more_zero_bytes(void **state)
{
    (void)state;
    assert_int_equal(sni_gw_accept_classify_bytes(NULL, 0), SNI_GW_ACCEPT_NEED_MORE);
}

/* ==========================================================================
 * sni_gw_accept_classify_fd -- I/O wrapper, over a real socketpair
 * ========================================================================== */

static void
test_classify_fd_peer_sends_nothing_bounded(void **state)
{
    (void)state;
    /* Guards against the blocking-recv(MSG_PEEK) DoS: a peer that opens the
     * connection and sends nothing must not hang this call.  Use a short
     * poll_timeout so the select()-timeout path is exercised, and assert
     * the call returns well within a small bound instead of hanging the
     * test process. */
    int fds[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    volatile int sig = 0;
    bool error = false;

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    enum sni_gw_accept_class cls = sni_gw_accept_classify_fd(fds[0], &error, &sig, 1);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (double)(end.tv_sec - start.tv_sec)
                     + (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    assert_true(error);
    assert_int_equal(cls, SNI_GW_ACCEPT_OTHER);
    assert_true(elapsed < 5.0);

    close(fds[0]);
    close(fds[1]);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_classify_sni_decoy_one_byte),
        cmocka_unit_test(test_classify_sni_decoy_full_record_header),
        cmocka_unit_test(test_classify_http_get_full),
        cmocka_unit_test(test_classify_http_get_partial),
        cmocka_unit_test(test_classify_plain_openvpn_prefix),
        cmocka_unit_test(test_classify_diverges_early),
        cmocka_unit_test(test_classify_g_prefix_length_byte_edge_case),
        cmocka_unit_test(test_classify_need_more_zero_bytes),
        cmocka_unit_test(test_classify_fd_peer_sends_nothing_bounded),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
