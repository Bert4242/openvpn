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
 * Unit tests for ps_sni.c: SNI passthrough header parsing and consumption.
 *
 * This file is compiled twice:
 *   sni_testdriver          - SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH defined,
 *                             exercises the generic byte-scan path (no OpenSSL).
 *   sni_openssl_testdriver  - no override, exercises the OpenSSL client_hello_cb
 *                             path on OpenSSL builds, generic path otherwise.
 *
 * The hand-crafted test packets are valid on both paths, so all assertions
 * apply equally to both test drivers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"


#include <setjmp.h>
#include <cmocka.h>

#include "buffer.h"
#include "socket.h"
#include "ps_sni.h"
#include "mock_msg.h"
#include "test_common.h"

/* =========================================================================
 * Minimal valid ClientHello carrying ALPN "hacky-sni-passthrough/1"
 *
 * Layout (all lengths big-endian):
 *   TLS record header  : 0x16 0x0301 record_len=77         (5 bytes)
 *   Handshake header   : 0x01 body_len=73                  (4 bytes)
 *   client_version     : 0x0303                            (2 bytes)
 *   random             : 32 zero-ish bytes                 (32 bytes)
 *   session_id         : len=0                             (1 byte)
 *   cipher_suites      : len=2, TLS_RSA_AES128_SHA(0x002f) (4 bytes)
 *   compression        : len=1, null(0x00)                 (2 bytes)
 *   extensions_len     : 30                                (2 bytes)
 *   ALPN extension     : type=0x0010 ext_data_len=26
 *                        list_len=24 proto_len=23
 *                        "hacky-sni-passthrough/1"         (30 bytes)
 *
 * Total: 82 bytes.  sni_passthrough_check_packet() must return 82.
 * ========================================================================= */
static const uint8_t valid_sni_pkt[] = {
    /* TLS record header */
    0x16,
    0x03,
    0x01,
    0x00,
    0x4d,
    /* Handshake header: ClientHello(1) body_len=73 */
    0x01,
    0x00,
    0x00,
    0x49,
    /* client_version */
    0x03,
    0x03,
    /* random (32 bytes) */
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    /* session_id: empty */
    0x00,
    /* cipher_suites: 1 suite */
    0x00,
    0x02,
    0x00,
    0x2f,
    /* compression_methods: null */
    0x01,
    0x00,
    /* extensions_len = 30 */
    0x00,
    0x1e,
    /* ALPN extension */
    0x00,
    0x10, /* ext_type = ALPN */
    0x00,
    0x1a, /* ext_data_len = 26 */
    0x00,
    0x18, /* protocol_list_len = 24 */
    0x17, /* protocol_len = 23 */
    'h',
    'a',
    'c',
    'k',
    'y',
    '-',
    's',
    'n',
    'i',
    '-',
    'p',
    'a',
    's',
    's',
    't',
    'h',
    'r',
    'o',
    'u',
    'g',
    'h',
    '/',
    '1',
};

/* ClientHello with ALPN "http/1.1" – hacky-sni-passthrough/1 not listed, should return -1 */
static const uint8_t wrong_alpn_pkt[] = {
    /* TLS record header: record_len=62 */
    0x16,
    0x03,
    0x01,
    0x00,
    0x3e,
    /* Handshake header: body_len=58 */
    0x01,
    0x00,
    0x00,
    0x3a,
    /* client_version */
    0x03,
    0x03,
    /* random */
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    /* session_id: empty */
    0x00,
    /* cipher_suites */
    0x00,
    0x02,
    0x00,
    0x2f,
    /* compression */
    0x01,
    0x00,
    /* extensions_len = 15 */
    0x00,
    0x0f,
    /* ALPN extension */
    0x00,
    0x10, /* ext_type = ALPN */
    0x00,
    0x0b, /* ext_data_len = 11 */
    0x00,
    0x09, /* protocol_list_len = 9 */
    0x08, /* protocol_len = 8 */
    'h',
    't',
    't',
    'p',
    '/',
    '1',
    '.',
    '1',
};

/* ClientHello with no extensions at all – no ALPN, should return -1 */
static const uint8_t no_ext_pkt[] = {
    /* TLS record header: record_len=45 */
    0x16,
    0x03,
    0x01,
    0x00,
    0x2d,
    /* Handshake header: body_len=41 */
    0x01,
    0x00,
    0x00,
    0x29,
    /* client_version */
    0x03,
    0x03,
    /* random */
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    /* session_id: empty */
    0x00,
    /* cipher_suites */
    0x00,
    0x02,
    0x00,
    0x2f,
    /* compression */
    0x01,
    0x00,
    /* no extensions field */
};

/*
 * A minimal ClientHello that carries BOTH an SNI extension (hostname
 * "vpn.example.com", 15 bytes) and ALPN "hacky-sni-passthrough/1".
 *
 * Layout (big-endian lengths):
 *   TLS record header   : 0x16 0x0301 record_len=118    (5 bytes)
 *   Handshake header    : 0x01 body_len=114              (4 bytes)
 *   client_version      : 0x0303                         (2 bytes)
 *   random              : 32 zero bytes                  (32 bytes)
 *   session_id          : len=0                          (1 byte)
 *   cipher_suites       : len=2, 0x002f                  (4 bytes)
 *   compression         : len=1, 0x00                    (2 bytes)
 *   extensions_len      : 66                             (2 bytes)
 *   SNI ext (0x0000)    : ext_data_len=19
 *                         list_len=17, name_type=0
 *                         name_len=15, "vpn.example.com" (23 bytes)
 *   ALPN ext (0x0010)   : ext_data_len=26
 *                         list_len=24, proto_len=23
 *                         "hacky-sni-passthrough/1" (30 bytes)
 *
 * Total: 123 bytes.  sni_passthrough_check_packet() must return 123.
 */
/*
 * Packet layout (all lengths big-endian):
 *
 *   TLS record header    : 0x16 0x0301 record_len=101    5 bytes
 *   Handshake header     : 0x01 body_len=97              4 bytes
 *   client_version       : 0x0303                        2 bytes
 *   random               : 32 zero bytes                32 bytes
 *   session_id           : len=0                         1 byte
 *   cipher_suites        : len=2, TLS_RSA_AES128_SHA     4 bytes
 *   compression          : len=1, null(0x00)             2 bytes
 *   extensions_len       : 54                            2 bytes
 *   SNI ext (0x0000)     : ext_data_len=20
 *                          list_len=18, name_type=0
 *                          name_len=15, "vpn.example.com"  24 bytes
 *   ALPN ext (0x0010)    : ext_data_len=26
 *                          list_len=24, proto_len=23
 *                          "hacky-sni-passthrough/1"        30 bytes
 *
 * Total: 5 + 101 = 106 bytes.
 */
static const uint8_t sni_and_alpn_pkt[] = {
    /* TLS record header: record_len = 101 */
    0x16,
    0x03,
    0x01,
    0x00,
    0x65,
    /* Handshake: ClientHello(1), body_len = 97 */
    0x01,
    0x00,
    0x00,
    0x61,
    /* client_version */
    0x03,
    0x03,
    /* random (32 bytes) */
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    /* session_id: empty */
    0x00,
    /* cipher_suites: 1 suite */
    0x00,
    0x02,
    0x00,
    0x2f,
    /* compression: null only */
    0x01,
    0x00,
    /* extensions_len = 54 */
    0x00,
    0x36,
    /* SNI extension */
    0x00,
    0x00, /* type = server_name */
    0x00,
    0x14, /* ext_data_len = 20 */
    0x00,
    0x12, /* server_name_list_len = 18 */
    0x00, /* name_type = host_name */
    0x00,
    0x0f, /* name_len = 15 */
    'v',
    'p',
    'n',
    '.',
    'e',
    'x',
    'a',
    'm',
    'p',
    'l',
    'e',
    '.',
    'c',
    'o',
    'm',
    /* ALPN extension */
    0x00,
    0x10, /* type = ALPN */
    0x00,
    0x1a, /* ext_data_len = 26 */
    0x00,
    0x18, /* protocol_list_len = 24 */
    0x17, /* protocol_len = 23 */
    'h',
    'a',
    'c',
    'k',
    'y',
    '-',
    's',
    'n',
    'i',
    '-',
    'p',
    'a',
    's',
    's',
    't',
    'h',
    'r',
    'o',
    'u',
    'g',
    'h',
    '/',
    '1',
};

/* ==========================================================================
 * Shared test helpers
 * ========================================================================== */

/* Default ctx: built-in ALPN, any hostname, ALPN required */
static const struct sni_pt_server_check_ctx ctx_default = { 0 };

/* Helper: allocate a stream_buf whose buf contains the given bytes */
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

/* ==========================================================================
 * sni_passthrough_check_packet tests
 * ========================================================================== */

static void
test_sni_check_packet_valid_openvpn_alpn(void **state)
{
    (void)state;
    int ret = sni_passthrough_check_packet(valid_sni_pkt, (int)sizeof(valid_sni_pkt),
                                           &ctx_default);
    assert_int_equal(ret, (int)sizeof(valid_sni_pkt));
}

static void
test_sni_check_packet_too_short(void **state)
{
    (void)state;
    assert_int_equal(sni_passthrough_check_packet(valid_sni_pkt, 4, &ctx_default), 0);
    assert_int_equal(sni_passthrough_check_packet(valid_sni_pkt, 0, &ctx_default), 0);
}

static void
test_sni_check_packet_not_handshake(void **state)
{
    (void)state;
    uint8_t buf[sizeof(valid_sni_pkt)];
    memcpy(buf, valid_sni_pkt, sizeof(valid_sni_pkt));
    buf[0] = 0x17;
    assert_int_equal(sni_passthrough_check_packet(buf, (int)sizeof(buf), &ctx_default), 0);
}

static void
test_sni_check_packet_not_clienthello(void **state)
{
    (void)state;
    uint8_t buf[sizeof(valid_sni_pkt)];
    memcpy(buf, valid_sni_pkt, sizeof(valid_sni_pkt));
    buf[5] = 0x02;
    assert_int_equal(sni_passthrough_check_packet(buf, (int)sizeof(buf), &ctx_default), -1);
}

static void
test_sni_check_packet_wrong_alpn(void **state)
{
    (void)state;
    assert_int_equal(
        sni_passthrough_check_packet(wrong_alpn_pkt, (int)sizeof(wrong_alpn_pkt),
                                     &ctx_default),
        -1);
}

static void
test_sni_check_packet_no_extensions(void **state)
{
    (void)state;
    assert_int_equal(
        sni_passthrough_check_packet(no_ext_pkt, (int)sizeof(no_ext_pkt), &ctx_default), -1);
}

static void
test_sni_check_packet_truncated_record(void **state)
{
    (void)state;
    assert_int_equal(
        sni_passthrough_check_packet(valid_sni_pkt, (int)sizeof(valid_sni_pkt) - 10,
                                     &ctx_default),
        0);
}

/* ignore_alpn=true: wrong ALPN → still accepted */
static void
test_sni_check_packet_ignore_alpn(void **state)
{
    (void)state;
    struct sni_pt_server_check_ctx ctx = { .ignore_alpn = true };
    /* wrong_alpn_pkt carries "http/1.1", not the configured token */
    int ret = sni_passthrough_check_packet(wrong_alpn_pkt, (int)sizeof(wrong_alpn_pkt), &ctx);
    assert_int_equal(ret, (int)sizeof(wrong_alpn_pkt));
}

/* ignore_alpn=true: packet with no ALPN extension at all → still accepted */
static void
test_sni_check_packet_ignore_alpn_no_ext(void **state)
{
    (void)state;
    struct sni_pt_server_check_ctx ctx = { .ignore_alpn = true };
    /* no_ext_pkt has no extensions at all */
    int ret = sni_passthrough_check_packet(no_ext_pkt, (int)sizeof(no_ext_pkt), &ctx);
    assert_int_equal(ret, (int)sizeof(no_ext_pkt));
}

/* hostname filter: packet carries "vpn.example.com", filter matches */
static void
test_sni_check_packet_hostname_match(void **state)
{
    (void)state;
    const char *hosts[] = { "vpn.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    int ret = sni_passthrough_check_packet(sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt),
                                           &ctx);
    assert_int_equal(ret, (int)sizeof(sni_and_alpn_pkt));
}

/* hostname filter: case-insensitive match */
static void
test_sni_check_packet_hostname_match_case(void **state)
{
    (void)state;
    const char *hosts[] = { "VPN.EXAMPLE.COM" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    int ret = sni_passthrough_check_packet(sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt),
                                           &ctx);
    assert_int_equal(ret, (int)sizeof(sni_and_alpn_pkt));
}

/* hostname filter: packet carries "vpn.example.com" but filter requires different host */
static void
test_sni_check_packet_hostname_mismatch(void **state)
{
    (void)state;
    const char *hosts[] = { "other.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    int ret = sni_passthrough_check_packet(sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt),
                                           &ctx);
    assert_int_equal(ret, -1);
}

/* hostname filter: any one of several hostnames matches */
static void
test_sni_check_packet_hostname_multi_match(void **state)
{
    (void)state;
    const char *hosts[] = { "other.example.com", "vpn.example.com", "another.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 3,
    };
    int ret = sni_passthrough_check_packet(sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt),
                                           &ctx);
    assert_int_equal(ret, (int)sizeof(sni_and_alpn_pkt));
}

/* hostname filter: packet has no SNI extension → filter rejects */
static void
test_sni_check_packet_hostname_filter_no_sni(void **state)
{
    (void)state;
    const char *hosts[] = { "vpn.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    /* valid_sni_pkt has only ALPN, no SNI extension */
    int ret = sni_passthrough_check_packet(valid_sni_pkt, (int)sizeof(valid_sni_pkt), &ctx);
    assert_int_equal(ret, -1);
}

/* ==========================================================================
 * sni_passthrough_check_and_consume_header tests
 *
 * These exercise the stream_buf state machine that socket.c calls at
 * stream_buf_read_dowork() when sni_passthrough_state == SNI_PT_PENDING.
 * ========================================================================== */

/* Valid SNI header: header is consumed, state transitions to SNI_PT_SUCCESS */
static void
test_sni_consume_header_valid(void **state)
{
    (void)state;
    struct stream_buf sb;
    make_stream_buf(&sb, valid_sni_pkt, (int)sizeof(valid_sni_pkt));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx_default);

    assert_true(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_SUCCESS);
    assert_int_equal(sb.buf.len, 0);

    free_stream_buf(&sb);
}

/* Valid SNI header followed by OpenVPN data: only the SNI header is consumed */
static void
test_sni_consume_header_with_trailing_data(void **state)
{
    (void)state;
    uint8_t trailing[] = { 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef };
    uint8_t combined[sizeof(valid_sni_pkt) + sizeof(trailing)];
    memcpy(combined, valid_sni_pkt, sizeof(valid_sni_pkt));
    memcpy(combined + sizeof(valid_sni_pkt), trailing, sizeof(trailing));

    struct stream_buf sb;
    make_stream_buf(&sb, combined, (int)sizeof(combined));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx_default);

    assert_true(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_SUCCESS);
    assert_int_equal(sb.buf.len, (int)sizeof(trailing));
    assert_memory_equal(BPTR(&sb.buf), trailing, sizeof(trailing));

    free_stream_buf(&sb);
}

/*
 * OpenVPN client without --sni-passthrough-hostname.
 * First byte != 0x16 → SNI_PT_DISABLED immediately.
 */
static void
test_sni_consume_header_openvpn_client(void **state)
{
    (void)state;
    uint8_t openvpn_data[] = { 0x00, 0x07, 0x38, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct stream_buf sb;
    make_stream_buf(&sb, openvpn_data, (int)sizeof(openvpn_data));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx_default);

    assert_false(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_DISABLED);

    free_stream_buf(&sb);
}

/* Wrong ALPN: complete packet recognised but rejected — error set, state DISABLED */
static void
test_sni_consume_header_tls_wrong_alpn(void **state)
{
    (void)state;
    struct stream_buf sb;
    make_stream_buf(&sb, wrong_alpn_pkt, (int)sizeof(wrong_alpn_pkt));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx_default);

    assert_false(result);
    assert_true(sb.error);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_DISABLED);

    free_stream_buf(&sb);
}

/* Buffer has fewer than 5 bytes: function returns false immediately */
static void
test_sni_consume_header_partial(void **state)
{
    (void)state;
    uint8_t partial[] = { 0x16, 0x03, 0x01 };
    struct stream_buf sb;
    make_stream_buf(&sb, partial, (int)sizeof(partial));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx_default);

    assert_false(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_PENDING);

    free_stream_buf(&sb);
}

/* ignore_alpn=true: wrong ALPN → still consumed */
static void
test_sni_consume_header_ignore_alpn(void **state)
{
    (void)state;
    struct sni_pt_server_check_ctx ctx = { .ignore_alpn = true };
    struct stream_buf sb;
    make_stream_buf(&sb, wrong_alpn_pkt, (int)sizeof(wrong_alpn_pkt));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx);

    assert_true(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_SUCCESS);

    free_stream_buf(&sb);
}

/* hostname filter match: packet with SNI "vpn.example.com" accepted */
static void
test_sni_consume_header_hostname_match(void **state)
{
    (void)state;
    const char *hosts[] = { "vpn.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    struct stream_buf sb;
    make_stream_buf(&sb, sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx);

    assert_true(result);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_SUCCESS);

    free_stream_buf(&sb);
}

/* hostname filter mismatch: complete packet recognised but rejected — error set, state DISABLED */
static void
test_sni_consume_header_hostname_mismatch(void **state)
{
    (void)state;
    const char *hosts[] = { "other.example.com" };
    struct sni_pt_server_check_ctx ctx = {
        .hostname_list = hosts,
        .hostname_count = 1,
    };
    struct stream_buf sb;
    make_stream_buf(&sb, sni_and_alpn_pkt, (int)sizeof(sni_and_alpn_pkt));

    bool result = sni_passthrough_check_and_consume_header(&sb, &ctx);

    assert_false(result);
    assert_true(sb.error);
    assert_int_equal(sb.sni_passthrough_state, SNI_PT_DISABLED);

    free_stream_buf(&sb);
}

/* ==========================================================================
 * sni_gateway_mode_from_string tests
 *
 * Covers the --sni-gateway / --sni-gateway-server mode argument parser
 * added as part of the SNI passthrough -> SNI gateway option rename.
 * ========================================================================== */

static void
test_sni_gateway_mode_from_string_drop(void **state)
{
    (void)state;
    assert_int_equal(sni_gateway_mode_from_string("drop"), SNI_GW_DROP);
}

static void
test_sni_gateway_mode_from_string_tls(void **state)
{
    (void)state;
    assert_int_equal(sni_gateway_mode_from_string("tls"), SNI_GW_TLS);
}

static void
test_sni_gateway_mode_from_string_http(void **state)
{
    (void)state;
    assert_int_equal(sni_gateway_mode_from_string("http"), SNI_GW_HTTP);
}

static void
test_sni_gateway_mode_from_string_unknown(void **state)
{
    (void)state;
    assert_int_equal(sni_gateway_mode_from_string("bogus"), -1);
    assert_int_equal(sni_gateway_mode_from_string(""), -1);
    /* case-sensitive: "Drop" must not match "drop" */
    assert_int_equal(sni_gateway_mode_from_string("Drop"), -1);
}

static void
test_sni_gateway_mode_from_string_null(void **state)
{
    (void)state;
    assert_int_equal(sni_gateway_mode_from_string(NULL), -1);
}

/* ==========================================================================
 * Test entry point
 * ========================================================================== */

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        /* sni_passthrough_check_packet – basic */
        cmocka_unit_test(test_sni_check_packet_valid_openvpn_alpn),
        cmocka_unit_test(test_sni_check_packet_too_short),
        cmocka_unit_test(test_sni_check_packet_not_handshake),
        cmocka_unit_test(test_sni_check_packet_not_clienthello),
        cmocka_unit_test(test_sni_check_packet_wrong_alpn),
        cmocka_unit_test(test_sni_check_packet_no_extensions),
        cmocka_unit_test(test_sni_check_packet_truncated_record),
        /* sni_passthrough_check_packet – ignore_alpn */
        cmocka_unit_test(test_sni_check_packet_ignore_alpn),
        cmocka_unit_test(test_sni_check_packet_ignore_alpn_no_ext),
        /* sni_passthrough_check_packet – hostname filter */
        cmocka_unit_test(test_sni_check_packet_hostname_match),
        cmocka_unit_test(test_sni_check_packet_hostname_match_case),
        cmocka_unit_test(test_sni_check_packet_hostname_mismatch),
        cmocka_unit_test(test_sni_check_packet_hostname_multi_match),
        cmocka_unit_test(test_sni_check_packet_hostname_filter_no_sni),

        /* sni_passthrough_check_and_consume_header */
        cmocka_unit_test(test_sni_consume_header_valid),
        cmocka_unit_test(test_sni_consume_header_with_trailing_data),
        cmocka_unit_test(test_sni_consume_header_openvpn_client),
        cmocka_unit_test(test_sni_consume_header_tls_wrong_alpn),
        cmocka_unit_test(test_sni_consume_header_partial),
        cmocka_unit_test(test_sni_consume_header_ignore_alpn),
        cmocka_unit_test(test_sni_consume_header_hostname_match),
        cmocka_unit_test(test_sni_consume_header_hostname_mismatch),

        /* sni_gateway_mode_from_string */
        cmocka_unit_test(test_sni_gateway_mode_from_string_drop),
        cmocka_unit_test(test_sni_gateway_mode_from_string_tls),
        cmocka_unit_test(test_sni_gateway_mode_from_string_http),
        cmocka_unit_test(test_sni_gateway_mode_from_string_unknown),
        cmocka_unit_test(test_sni_gateway_mode_from_string_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
