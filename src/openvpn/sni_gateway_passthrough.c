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


#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
#include "openssl_compat.h"
#endif
#include "socket.h"
#include "error.h"
#include "crypto.h"
#include "sni_gateway_passthrough.h"

/*
 * SNI passthrough support -- implements the --sni-gateway "sni" mode
 * (client) and --sni-gateway-server "sni" mode (server).
 *
 * Allows OpenVPN TCP connections to pass through SNI-aware TCP proxies such
 * as Traefik (passthrough mode) on any port, without any double encryption.
 *
 * SNI-aware proxies read the hostname from the first bytes of the TCP stream
 * and route the connection accordingly.  They expect those bytes to be
 * formatted as a ClientHello record (the standard carrier for SNI in TCP).
 *
 *   Client (--sni-gateway sni --sni-gateway-host <hostname>):
 *     Prepends a single SNI routing header — a ClientHello record
 *     carrying the given hostname — before the OpenVPN protocol bytes.
 *     The proxy reads the hostname, routes the stream to the right backend,
 *     and forwards all bytes (including the header) maybe unchanged.
 *
 *   Server (--sni-gateway-server sni):
 *     Receives the routed stream, reads and discards the SNI routing header,
 *     then proceeds with the normal OpenVPN protocol. Openvpn clients that
 *     do not send the header are detected automatically and handled normally.
 *
 * No session of any kind is established by the routing header — it is
 * discarded immediately.  No encryption layer is added; OpenVPN's own
 * control-channel and data-channel security are used unchanged.
 */

/* Default ALPN protocol name when --sni-gateway-alpn is not set. */
#define SNI_PT_DEFAULT_ALPN     "hacky-sni-passthrough/1"
#define SNI_PT_DEFAULT_ALPN_LEN 23u /* strlen("hacky-sni-passthrough/1") */

static const char *sni_pt_default_alpn_list[] = { SNI_PT_DEFAULT_ALPN };

/*
 * Resolve alpn_list / alpn_count to an effective list.
 * When the caller passes an empty list, use the built-in default.
 * Writes the resolved pointer and count through the out-params.
 */
static void
sni_pt_resolve_alpn(const char *const *alpn_list, int alpn_count,
                    const char *const **out_list, int *out_count)
{
    if (alpn_count > 0 && alpn_list)
    {
        *out_list = alpn_list;
        *out_count = alpn_count;
    }
    else
    {
        *out_list = (const char *const *)sni_pt_default_alpn_list;
        *out_count = 1;
    }
}

/*
 * Write all ALPN tokens as wire-format length-prefixed entries into buf.
 * Returns false on overflow or a token longer than 255 bytes.
 */
static bool
sni_pt_build_alpn_proto_list(struct buffer *buf,
                             const char *const *alpn_list, int alpn_count)
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
        if (!buf_write_u8(buf, (uint8_t)name_len)
            || !buf_write(buf, name, name_len))
        {
            return false;
        }
    }
    return true;
}


#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)

static size_t
sni_passthrough_build_client_hello(uint8_t *buf, size_t bufsz, const char *sni,
                                   const char *const *alpn_list, int alpn_count)
{
    size_t ret = 0;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    unsigned char alpn_wire_raw[4096]; /* room for many tokens */
    struct buffer alpn_wire;
    const char *const *eff_list;
    int eff_count;

    if (!sni || !*sni)
    {
        return 0;
    }

    sni_pt_resolve_alpn(alpn_list, alpn_count, &eff_list, &eff_count);
    buf_set_write(&alpn_wire, alpn_wire_raw, sizeof(alpn_wire_raw));
    if (!sni_pt_build_alpn_proto_list(&alpn_wire, eff_list, eff_count)
        || !BLEN(&alpn_wire))
    {
        return 0;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        goto cleanup;
    }

    ssl = SSL_new(ctx);
    if (!ssl)
    {
        goto cleanup;
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
    {
        goto cleanup;
    }

    SSL_set_bio(ssl, rbio, wbio);
    rbio = NULL;
    wbio = NULL;

    SSL_set_connect_state(ssl);

    if (!SSL_set_tlsext_host_name(ssl, sni))
    {
        goto cleanup;
    }

    if (SSL_set_alpn_protos(ssl, BPTR(&alpn_wire), (unsigned int)BLEN(&alpn_wire)) != 0)
    {
        goto cleanup;
    }

    int handshake_ret = SSL_do_handshake(ssl);
    if (handshake_ret != 1)
    {
        int ssl_err = SSL_get_error(ssl, handshake_ret);
        if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
        {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            msg(M_NONFATAL, "--sni-gateway sni: SSL_do_handshake failed: %s", err_buf);
            goto cleanup;
        }
        else
        {
            /* SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE are not fatal to our usage */
        }
    }

    BIO *wbio_peek = SSL_get_wbio(ssl);
    if (!wbio_peek)
    {
        goto cleanup;
    }
    else
    {
        size_t pending = (size_t)BIO_ctrl_pending(wbio_peek);
        if (!pending || pending > bufsz)
        {
            msg(M_NONFATAL, "--sni-gateway sni: ClientHello too large: pending=%zu bufsz=%zu", pending, bufsz);
            goto cleanup;
        }

        int n = BIO_read(wbio_peek, buf, (int)pending);
        if (n <= 0 || (size_t)n != pending)
        {
            goto cleanup;
        }
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

#else /* generic byte-scan path: LibreSSL, mbedTLS, wolfSSL, … */

/*
 * Template-based ClientHello builder for non-OpenSSL backends.
 *
 * The fixed portions of the ClientHello are stored as small named arrays.
 * The builder writes them sequentially via the OpenVPN buf API, inserting
 * computed length fields between sections so no back-patching is needed.
 * Variable fields (SNI, ALPN) are written through dedicated TLV helpers.
 * Ephemeral fields (random, session-id, key shares) are randomised in place.
 *
 * The template was originally captured from OpenSSL 3.x with a 21-byte SNI
 * and "hacky-sni-passthrough" (21 bytes) as the ALPN token.
 */

/* clang-format off */

/* TLS record: content_type=Handshake(0x16) + legacy_version=TLS1.0 */
static const uint8_t sni_pt_tls_hdr[3] = { 0x16, 0x03, 0x01 };

/* Handshake: msg_type=ClientHello(0x01) */
static const uint8_t sni_pt_hs_type[1] = { 0x01 };

/* ClientHello: client_version=TLS1.2 */
static const uint8_t sni_pt_client_version[2] = { 0x03, 0x03 };

/* session_id_len=32 */
static const uint8_t sni_pt_session_id_len[1] = { 0x20 };

/* cipher_suites_len=60 (30 suites) + null compression */
static const uint8_t sni_pt_cipher_and_comp[64] = {
    0x00,0x3c,
    0x13,0x02,0x13,0x03,0x13,0x01,0xc0,0x2c,
    0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,
    0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e,
    0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,
    0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14,
    0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,
    0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c,
    0x00,0x35,0x00,0x2f,
    0x01,0x00,
};

/* renegotiation_info ext: type(0xff01) + ext_data_len(1) + data(0x00) */
static const uint8_t sni_pt_renegotiation_info[5] = { 0xff, 0x01, 0x00, 0x01, 0x00 };

/*
 * The suffix is split into two halves around the ALPN extension, which is
 * now built dynamically so that --sni-gateway-alpn can override it.
 *
 * sni_pt_suffix_pre_alpn  – extensions before the ALPN extension (34 bytes)
 * sni_pt_suffix_post_alpn – extensions after the ALPN extension (1352 bytes)
 *
 * The default ALPN ("hacky-sni-passthrough/1") is 30 bytes on the wire:
 *   ext_type(2) + ext_data_len(2) + list_len(2) + proto_len(1) + name(23)
 * So the default total suffix = 34 + 30 + 1352 = 1416 bytes, matching the
 * original SNI_PT_SUFFIX_LEN.
 */
static const uint8_t sni_pt_suffix_pre_alpn[34] = {
    /* ec_point_formats */
    0x00,0x0b,0x00,0x04,0x03,0x00,0x01,0x02,
    /* supported_groups */
    0x00,0x0a,0x00,0x12,0x00,0x10,0x11,0xec,
    0x00,0x1d,0x00,0x17,0x00,0x1e,0x00,0x18,
    0x00,0x19,0x01,0x00,0x01,0x01,
    /* session_ticket (empty) */
    0x00,0x23,0x00,0x00,
};

static const uint8_t sni_pt_suffix_post_alpn[1352] = {
    /* encrypt_then_mac */
    0x00,0x16,0x00,0x00,
    /* extended_master_secret */
    0x00,0x17,0x00,0x00,
    /* signature_algorithms */
    0x00,0x0d,0x00,0x36,0x00,0x34,0x09,0x05,
    0x09,0x06,0x09,0x04,0x04,0x03,0x05,0x03,
    0x06,0x03,0x08,0x07,0x08,0x08,0x08,0x1a,
    0x08,0x1b,0x08,0x1c,0x08,0x09,0x08,0x0a,
    0x08,0x0b,0x08,0x04,0x08,0x05,0x08,0x06,
    0x04,0x01,0x05,0x01,0x06,0x01,0x03,0x03,
    0x03,0x01,0x03,0x02,0x04,0x02,0x05,0x02,
    0x06,0x02,
    /* supported_versions: TLS 1.3, TLS 1.2 */
    0x00,0x2b,0x00,0x05,0x04,0x03,0x04,0x03,0x03,
    /* psk_key_exchange_modes */
    0x00,0x2d,0x00,0x02,0x01,0x01,
    /* key_share (1262 bytes: 4 hdr + 2 list_len + key shares) */
    0x00,0x33,0x04,0xea,0x04,0xe8,
    /* ML-KEM group 0x11ec, key len 0x04c0=1216 - overwritten at use time */
    0x11,0xec,0x04,0xc0,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* x25519 group 0x001d, key len 0x0020=32 - overwritten at use time */
    0x00,0x1d,0x00,0x20,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* compress_certificate */
    0x00,0x1b,0x00,0x05,0x04,0x00,0x01,0x00,0x03
};
/* clang-format on */

#define SNI_PT_SUFFIX_PRE_ALPN_LEN  34u
#define SNI_PT_SUFFIX_POST_ALPN_LEN 1352u

/* Offsets of ephemeral key fields within sni_pt_suffix_post_alpn[] */
#define SNI_PT_POST_ALPN_MLKEM_OFF  91u   /* ML-KEM key data (1216 bytes) */
#define SNI_PT_POST_ALPN_MLKEM_LEN  1216u
#define SNI_PT_POST_ALPN_X25519_OFF 1311u /* x25519 key data (32 bytes) */
#define SNI_PT_POST_ALPN_X25519_LEN 32u

/*
 * Write a TLS SNI extension into buf.
 *
 * Wire layout: ext_type(2) + ext_data_len(2) +
 *              server_name_list_len(2) + name_type(1) + name_len(2) + name(sni_len)
 */
static bool
buf_write_sni_ext(struct buffer *buf, const char *sni, size_t sni_len)
{
    uint16_t list_len = (uint16_t)(3 + sni_len);      /* name_type(1) + name_len(2) + name */
    uint16_t ext_data_len = (uint16_t)(2 + list_len); /* list_len field + list */

    return buf_write_u16(buf, 0x0000)                 /* server_name ext type */
           && buf_write_u16(buf, ext_data_len)
           && buf_write_u16(buf, list_len)
           && buf_write_u8(buf, 0x00) /* name_type = host_name */
           && buf_write_u16(buf, (uint16_t)sni_len)
           && buf_write(buf, sni, sni_len);
}

/*
 * Write a TLS ALPN extension into buf.
 *
 * Wire layout: ext_type(2) + ext_data_len(2) +
 *              protocol_list_len(2) + proto_list
 */
static bool
buf_write_alpn_ext(struct buffer *buf, const struct buffer *proto_list)
{
    size_t list_len = BLENZ(proto_list);
    uint16_t ext_data_len = (uint16_t)(2 + list_len); /* list_len field + list */

    return buf_write_u16(buf, 0x0010)                 /* ALPN ext type */
           && buf_write_u16(buf, ext_data_len)
           && buf_write_u16(buf, (uint16_t)list_len)
           && buf_write(buf, BPTR(proto_list), list_len);
}

static size_t
sni_passthrough_build_client_hello(uint8_t *raw_buf, size_t bufsz, const char *sni,
                                   const char *const *alpn_list, int alpn_count)
{
    unsigned char alpn_proto_raw[4096];
    struct buffer alpn_buf;
    const char *const *eff_list;
    int eff_count;

#if defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
    msg(M_INFO, "--sni-gateway sni: sni_passthrough_build_client_hello SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif

    if (!sni || !*sni)
    {
        return 0;
    }

    sni_pt_resolve_alpn(alpn_list, alpn_count, &eff_list, &eff_count);
    buf_set_write(&alpn_buf, alpn_proto_raw, sizeof(alpn_proto_raw));
    if (!sni_pt_build_alpn_proto_list(&alpn_buf, eff_list, eff_count)
        || !BLEN(&alpn_buf))
    {
        msg(M_NONFATAL, "--sni-gateway-alpn: ALPN token list too long or empty");
        return 0;
    }

    size_t sni_len = strlen(sni);
    /* SNI ext total: type(2)+ext_data_len(2)+list_len(2)+name_type(1)+name_len(2)+name */
    size_t sni_ext_size = 9 + sni_len;
    /* ALPN ext total: type(2)+ext_data_len(2)+list_len(2)+proto_list */
    size_t alpn_ext_size = 6 + BLENZ(&alpn_buf);
    /* All extensions: renego(5) + SNI + pre_alpn + ALPN + post_alpn */
    size_t exts_size = sizeof(sni_pt_renegotiation_info) + sni_ext_size
                       + SNI_PT_SUFFIX_PRE_ALPN_LEN + alpn_ext_size
                       + SNI_PT_SUFFIX_POST_ALPN_LEN;
    /* Handshake body: version(2)+random(32)+sid_len(1)+sid(32)+cs_and_comp(64)+exts_len(2)+exts */
    size_t hs_body_size = sizeof(sni_pt_client_version) + 32
                          + sizeof(sni_pt_session_id_len) + 32
                          + sizeof(sni_pt_cipher_and_comp) + 2 + exts_size;
    /* Total packet: TLS hdr(3)+rec_len(2) + HS type(1)+HS len(3) + HS body */
    size_t total = sizeof(sni_pt_tls_hdr) + 2
                   + sizeof(sni_pt_hs_type) + 3
                   + hs_body_size;

    if (total > bufsz || total > 0xffffU + 5)
    {
        msg(M_NONFATAL, "--sni-gateway sni: SNI hostname too long");
        return 0;
    }

    uint8_t random_bytes[32];
    uint8_t session_id[32];
    prng_bytes(random_bytes, sizeof(random_bytes));
    prng_bytes(session_id, sizeof(session_id));

    struct buffer buf;
    buf_set_write(&buf, raw_buf, (int)bufsz);

    /* TLS record header */
    buf_write(&buf, sni_pt_tls_hdr, sizeof(sni_pt_tls_hdr));
    buf_write_u16(&buf, (uint16_t)(total - 5)); /* record length */

    /* Handshake header */
    buf_write(&buf, sni_pt_hs_type, sizeof(sni_pt_hs_type));
    buf_write_u8(&buf, (uint8_t)((hs_body_size >> 16) & 0xff)); /* handshake length: */
    buf_write_u16(&buf, (uint16_t)(hs_body_size & 0xffff));     /*   3-byte big-endian */

    /* ClientHello body */
    buf_write(&buf, sni_pt_client_version, sizeof(sni_pt_client_version));
    buf_write(&buf, random_bytes, sizeof(random_bytes));
    buf_write(&buf, sni_pt_session_id_len, sizeof(sni_pt_session_id_len));
    buf_write(&buf, session_id, sizeof(session_id));
    buf_write(&buf, sni_pt_cipher_and_comp, sizeof(sni_pt_cipher_and_comp));
    buf_write_u16(&buf, (uint16_t)exts_size); /* extensions_len */

    /* Extensions */
    buf_write(&buf, sni_pt_renegotiation_info, sizeof(sni_pt_renegotiation_info));
    buf_write_sni_ext(&buf, sni, sni_len);
    buf_write(&buf, sni_pt_suffix_pre_alpn, SNI_PT_SUFFIX_PRE_ALPN_LEN);
    buf_write_alpn_ext(&buf, &alpn_buf);
    buf_write(&buf, sni_pt_suffix_post_alpn, SNI_PT_SUFFIX_POST_ALPN_LEN);

    ASSERT(BLEN(&buf) == (int)total);

    /* Randomise ephemeral key shares inside sni_pt_suffix_post_alpn */
    uint8_t *post_alpn = BPTR(&buf) + (total - SNI_PT_SUFFIX_POST_ALPN_LEN);
    prng_bytes(post_alpn + SNI_PT_POST_ALPN_MLKEM_OFF, SNI_PT_POST_ALPN_MLKEM_LEN);
    prng_bytes(post_alpn + SNI_PT_POST_ALPN_X25519_OFF, SNI_PT_POST_ALPN_X25519_LEN);

    return total;
}

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */

/*
 * Client side (--sni-gateway sni): send the SNI routing header,
 * then return. The OpenVPN protocol will follow immediately after.
 */
bool
sni_passthrough_send_client_hello(socket_descriptor_t sd, const char *sni,
                                  const char *const *alpn_list, int alpn_count)
{
    uint8_t buf[4096];
    size_t len;
    ssize_t sent;

    len = sni_passthrough_build_client_hello(buf, sizeof(buf), sni,
                                             alpn_list, alpn_count);

    if (!len)
    {
        msg(M_NONFATAL, "--sni-gateway sni: failed to build SNI routing header");
        goto error;
    }

    sent = 0;
    while (sent < (ssize_t)len)
    {
        ssize_t n = send(sd, (const char *)(buf + sent), (int)(len - sent), MSG_NOSIGNAL);
        if (n <= 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "--sni-gateway sni: send() failed");
            goto error;
        }
        sent += n;
    }

    msg(M_INFO, "--sni-gateway sni: sent SNI routing header (hostname: %s)", sni);
    return true;

error:
    return false;
}


#if defined(ENABLE_CRYPTO_OPENSSL) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)

/*
 * State passed through the client_hello_cb arg pointer so we avoid globals.
 */
struct sni_pt_cb_ctx
{
    /* resolved ALPN list (never NULL after init) */
    const char *const *alpn_list;
    int alpn_count;
    bool ignore_alpn;

    /* server hostname filter (NULL / 0 → any hostname accepted) */
    const char *const *hostname_list;
    int hostname_count;

    /* results set by the callback */
    int alpn_matched;
    int hostname_matched; /* 1 = matched or no filter; 0 = filter present and failed */
    bool callback_fired;  /* true if client_hello_cb was invoked (complete ClientHello) */
};

/*
 * client_hello_cb fires on the raw ClientHello before any certificate is
 * needed, in both TLS 1.2 and TLS 1.3.  We inspect the SNI and ALPN
 * extensions to apply the configured filters.
 */
static int
sni_passthrough_client_hello_cb(SSL *ssl, int *alert, void *arg)
{
    struct sni_pt_cb_ctx *cb = (struct sni_pt_cb_ctx *)arg;
    cb->callback_fired = true;

    /* ---- Hostname check ---- */
    if (cb->hostname_count > 0)
    {
        const unsigned char *sni_data = NULL;
        size_t sni_len = 0;
        cb->hostname_matched = 0;

        if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name,
                                      &sni_data, &sni_len)
            && sni_data && sni_len >= 5)
        {
            /*
             * SNI ext_data wire format:
             *   server_name_list_len (2) + name_type (1) + name_len (2) + name
             */
            const unsigned char *p = sni_data + 2; /* skip list_len */
            const unsigned char *end = sni_data + sni_len;
            while (p + 3 <= end && !cb->hostname_matched)
            {
                /* name_type must be 0 (host_name) */
                unsigned int ntype = p[0];
                unsigned int nlen = ((unsigned int)p[1] << 8) | p[2];
                p += 3;
                if (p + nlen > end)
                {
                    break;
                }
                if (ntype == 0)
                {
                    for (int i = 0; i < cb->hostname_count; i++)
                    {
                        if (nlen == strlen(cb->hostname_list[i])
                            && strncasecmp((const char *)p, cb->hostname_list[i], nlen) == 0)
                        {
                            cb->hostname_matched = 1;
                            msg(M_INFO,
                                "--sni-gateway-server sni: client_hello_cb: %s hostname matched",
                                cb->hostname_list[i]);
                            break;
                        }
                    }
                }
                p += nlen;
            }
        }
        if (!cb->hostname_matched)
        {
            msg(M_WARN,
                "--sni-gateway-server sni: client_hello_cb: hostname not in allowed list, rejecting");
        }
    }
    else
    {
        cb->hostname_matched = 1; /* no filter → always pass */
    }

    /* ---- ALPN check ---- */
    if (cb->ignore_alpn)
    {
        cb->alpn_matched = 1;
    }
    else
    {
        const unsigned char *alpn_data = NULL;
        size_t alpn_len = 0;

        if (SSL_client_hello_get0_ext(ssl,
                                      TLSEXT_TYPE_application_layer_protocol_negotiation,
                                      &alpn_data, &alpn_len)
            && alpn_data && alpn_len > 4)
        {
            /* ALPN wire format: protocol_list_len(2) + proto_len(1) + proto … */
            const unsigned char *p = alpn_data + 2;
            const unsigned char *end = alpn_data + alpn_len;

            while (p < end && !cb->alpn_matched)
            {
                unsigned int plen = *p++;
                if (p + plen > end)
                {
                    break;
                }
                for (int i = 0; i < cb->alpn_count; i++)
                {
                    const char *name = cb->alpn_list[i];
                    size_t name_len = strlen(name);
                    if (plen == name_len && memcmp(p, name, plen) == 0)
                    {
                        cb->alpn_matched = 1;
                        msg(M_INFO,
                            "--sni-gateway-server sni: client_hello_cb: %s ALPN matched",
                            name);
                        break;
                    }
                }
                p += plen;
            }
        }
    }

    /* Always return success — we are only inspecting, not blocking. */
    return SSL_CLIENT_HELLO_SUCCESS;
}

int
sni_passthrough_check_packet(const unsigned char *pkt, int pkt_len,
                             const struct sni_pt_server_check_ctx *ctx)
{
    struct sni_pt_cb_ctx cb_ctx;
    int consumed = 0;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;

    cb_ctx.ignore_alpn = ctx->ignore_alpn;
    cb_ctx.hostname_list = ctx->hostname_list;
    cb_ctx.hostname_count = ctx->hostname_count;
    cb_ctx.alpn_matched = 0;
    cb_ctx.hostname_matched = 0;
    cb_ctx.callback_fired = false;

    if (ctx->ignore_alpn)
    {
        cb_ctx.alpn_list = NULL;
        cb_ctx.alpn_count = 0;
    }
    else
    {
        sni_pt_resolve_alpn(ctx->alpn_list, ctx->alpn_count,
                            &cb_ctx.alpn_list, &cb_ctx.alpn_count);
    }

    /*
     * Mirror the generic path's early guards so both paths agree on obviously
     * non-SNI-header packets without spinning up the SSL machinery.
     */
    if (pkt_len < 5 || pkt[0] != 0x16)
    {
        return 0;
    }
    {
        int hs_record_len = ((int)pkt[3] << 8) | (int)pkt[4];
        if (hs_record_len > 0x4000)
        {
            return -1; /* garbage or deliberate oversized record */
        }
        if (5 + hs_record_len > pkt_len)
        {
            return 0; /* record is incomplete; wait for more data */
        }
    }

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx)
    {
        goto cleanup;
    }
    /* client_hello_cb fires on the raw ClientHello before any certificate
     * is required, unlike the ALPN select callback which needs a cert. */
    SSL_CTX_set_client_hello_cb(ssl_ctx, sni_passthrough_client_hello_cb, &cb_ctx);

    ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        goto cleanup;
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
    {
        goto cleanup;
    }

    SSL_set_bio(ssl, rbio, wbio);
    rbio = NULL;
    wbio = NULL;

    /* Feed the raw ClientHello into the read BIO and drive the state machine.
     * SSL_accept will "fail" (no cert, no full handshake) but the callback
     * fires before that and is all we need. */
    BIO_write(SSL_get_rbio(ssl), pkt, pkt_len);
    SSL_accept(ssl);

    size_t remaining = BIO_ctrl_pending(SSL_get_rbio(ssl));
    if (remaining <= (size_t)pkt_len)
    {
        consumed = pkt_len - (int)remaining;
    }
    else
    {
        msg(M_WARN, "--sni-gateway-server sni: BIO_ctrl_pending returned %zu > pkt_len %d",
            remaining, pkt_len);
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
    if (ssl_ctx)
    {
        SSL_CTX_free(ssl_ctx);
    }

    if (cb_ctx.alpn_matched && cb_ctx.hostname_matched)
    {
        if (consumed)
        {
            msg(M_INFO, "--sni-gateway-server sni: sni_passthrough_check_packet consumed");
            return consumed;
        }
        else
        {
            msg(M_WARN, "--sni-gateway-server sni: routing header found but not consumed");
            return 0;
        }
    }
    /*
     * The early guards above guarantee the record is complete.  If we reach
     * here, either the callback didn't fire (not a valid ClientHello) or at
     * least one filter was not satisfied.  Either way, reject.
     */
    return -1;
}

#else /* generic byte-scan path: LibreSSL, mbedTLS, wolfSSL, … */

/*
 * OpenSSL's SSL_CTX_set_client_hello_cb / SSL_client_hello_get0_ext are not
 * available on LibreSSL, mbedTLS, wolfSSL, or other non-OpenSSL backends.
 * Instead we manually parse the raw ClientHello to find the ALPN extension
 * (type 0x0010) and verify the configured ALPN token appears in the
 * ProtocolNameList.
 *
 * ClientHello layout (all lengths big-endian):
 *   TLS record header  : type(1) + version(2) + record_len(2)        = 5 bytes
 *   Handshake header   : hs_type(1) + body_len(3)                    = 4 bytes
 *   ClientHello body   : client_version(2) + random(32)              = 34 bytes
 *                        session_id_len(1) + session_id(var)
 *                        cipher_suites_len(2) + cipher_suites(var)
 *                        compression_len(1) + compression(var)
 *                        extensions_len(2) + extensions(var)
 *   Each extension     : ext_type(2) + ext_data_len(2) + ext_data(var)
 *   ALPN ext_data      : proto_list_len(2) + proto_name_len(1) + name(var) ...
 */
int
sni_passthrough_check_packet(const unsigned char *pkt, int pkt_len,
                             const struct sni_pt_server_check_ctx *ctx)
{
    const char *const *eff_alpn_list = NULL;
    int eff_alpn_count = 0;
#if defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
    msg(M_INFO, "--sni-gateway-server sni: sni_passthrough_check_packet SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif

    if (!ctx->ignore_alpn)
    {
        sni_pt_resolve_alpn(ctx->alpn_list, ctx->alpn_count,
                            &eff_alpn_list, &eff_alpn_count);
    }

/*
 * Macro: advance cursor by n bytes.
 * Returns -1 (reject) on overrun: we only reach this macro after confirming
 * the record is fully received, so any internal overrun means malformed data.
 */
#define SNI_PT_ADVANCE(p, n, end) \
    do                            \
    {                             \
        if ((p) + (n) > (end))    \
        {                         \
            return -1;            \
        }                         \
        (p) += (n);               \
    } while (0)

/* Macro: read 2-byte big-endian uint16 at p (without advancing) */
#define SNI_PT_READ16(p) ((unsigned int)((p)[0]) << 8 | (unsigned int)((p)[1]))

    /* Need at least TLS record header (5 bytes) */
    if (pkt_len < 5)
    {
        return 0;
    }

    /* Verify TLS handshake content type */
    if (pkt[0] != 0x16)
    {
        return 0;
    }

    /* TLS record length is at bytes [3..4] (big-endian) */
    int record_len = (int)SNI_PT_READ16(pkt + 3);
    /* Reject records exceeding the TLS maximum plaintext size (RFC 5246 §6.2.1).
     * A larger value is either garbage or a deliberate attempt to exhaust our buffer. */
    if (record_len > 0x4000)
    {
        return -1;
    }
    int total = 5 + record_len;
    if (total > pkt_len)
    {
        return 0; /* record is incomplete; wait for more data */
    }

    /* From here the full record is in hand — any parse failure is a rejection. */
    const unsigned char *end = pkt + total;
    const unsigned char *p = pkt + 5; /* skip TLS record header */

    /* Handshake header: type(1) + 24-bit body length */
    if (p + 4 > end)
    {
        return -1;
    }
    if (p[0] != 0x01) /* ClientHello */
    {
        return -1;
    }
    p += 4;

    /* ClientHello body: client_version(2) + random(32) = 34 bytes */
    SNI_PT_ADVANCE(p, 34, end);

    /* session_id: length(1) + data */
    if (p + 1 > end)
    {
        return -1;
    }
    unsigned int sid_len = *p;
    SNI_PT_ADVANCE(p, 1 + sid_len, end);

    /* cipher_suites: length(2) + data */
    if (p + 2 > end)
    {
        return -1;
    }
    unsigned int cs_len = SNI_PT_READ16(p);
    SNI_PT_ADVANCE(p, 2 + cs_len, end);

    /* compression_methods: length(1) + data */
    if (p + 1 > end)
    {
        return -1;
    }
    unsigned int cm_len = *p;
    SNI_PT_ADVANCE(p, 1 + cm_len, end);

    /*
     * Single pass over all extensions, collecting:
     *   hostname_ok – true when the SNI hostname filter is satisfied
     *   alpn_ok     – true when the ALPN filter is satisfied
     */
    int hostname_ok = (ctx->hostname_count == 0) ? 1 : 0;
    int alpn_ok = ctx->ignore_alpn ? 1 : 0;

    /* If all filters are trivially satisfied and there are no extensions, accept. */
    if (hostname_ok && alpn_ok && p + 2 > end)
    {
        return total;
    }

    /* extensions: total length(2) */
    if (p + 2 > end)
    {
        return -1;
    }
    unsigned int exts_len = SNI_PT_READ16(p);
    p += 2;

    const unsigned char *exts_end = p + exts_len;
    if (exts_end > end)
    {
        return -1;
    }

    const unsigned char *ep = p;
    while (ep + 4 <= exts_end)
    {
        unsigned int ext_type = SNI_PT_READ16(ep);
        unsigned int ext_len = SNI_PT_READ16(ep + 2);
        ep += 4;

        if (ep + ext_len > exts_end)
        {
            return -1;
        }

        if (ext_type == 0x0000 && !hostname_ok) /* server_name */
        {
            /*
             * SNI ext_data: server_name_list_len(2) + name_type(1) +
             *               name_len(2) + name
             */
            const unsigned char *sp = ep;
            const unsigned char *sp_end = ep + ext_len;
            if (sp + 2 > sp_end)
            {
                ep += ext_len;
                continue;
            }
            unsigned int list_len = SNI_PT_READ16(sp);
            sp += 2;
            const unsigned char *list_end = sp + list_len;
            if (list_end > sp_end)
            {
                ep += ext_len;
                continue;
            }
            while (sp + 3 <= list_end && !hostname_ok)
            {
                unsigned int ntype = sp[0];
                unsigned int nlen = SNI_PT_READ16(sp + 1);
                sp += 3;
                if (sp + nlen > list_end)
                {
                    break;
                }
                if (ntype == 0) /* host_name */
                {
                    for (int i = 0; i < ctx->hostname_count; i++)
                    {
                        if (nlen == strlen(ctx->hostname_list[i])
                            && strncasecmp((const char *)sp, ctx->hostname_list[i], nlen) == 0)
                        {
                            hostname_ok = 1;
                            msg(M_INFO,
                                "--sni-gateway-server sni: %s hostname matched (generic path)",
                                ctx->hostname_list[i]);
                            break;
                        }
                    }
                }
                sp += nlen;
            }
        }
        else if (ext_type == 0x0010 && !alpn_ok) /* ALPN */
        {
            /* ALPN extension data: ProtocolNameList length(2) + entries */
            if (ext_len < 2)
            {
                ep += ext_len;
                continue;
            }
            const unsigned char *ap = ep;
            unsigned int list_len = SNI_PT_READ16(ap);
            ap += 2;
            const unsigned char *ap_end = ap + list_len;
            if (ap_end > ep + ext_len)
            {
                ep += ext_len;
                continue;
            }

            while (ap + 1 <= ap_end && !alpn_ok)
            {
                unsigned int name_len = *ap++;
                if (ap + name_len > ap_end)
                {
                    break;
                }
                for (int k = 0; k < eff_alpn_count; k++)
                {
                    const char *exp = eff_alpn_list[k];
                    size_t exp_len = strlen(exp);
                    if (name_len == (unsigned int)exp_len
                        && memcmp(ap, exp, name_len) == 0)
                    {
                        alpn_ok = 1;
                        msg(M_INFO,
                            "--sni-gateway-server sni: %s ALPN matched (generic path)",
                            exp);
                        break;
                    }
                }
                ap += name_len;
            }

            if (!alpn_ok)
            {
                /* ALPN extension present but no token matched in a complete packet. */
                return -1;
            }
        }

        ep += ext_len;
    }

#undef SNI_PT_ADVANCE
#undef SNI_PT_READ16

    if (hostname_ok && alpn_ok)
    {
        return total;
    }
    /*
     * We parsed the complete ClientHello but at least one filter was not
     * satisfied.  Waiting for more data cannot help — reject the connection.
     */
    if (!hostname_ok && ctx->hostname_count > 0)
    {
        msg(M_WARN,
            "--sni-gateway-server sni: hostname not in allowed list, rejecting (generic path)");
    }
    return -1;
}

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */


/*
 * Server side (--sni-gateway-server sni): detect and consume the SNI routing
 * header prepended by --sni-gateway sni clients before the OpenVPN
 * stream begins.
 */
bool
sni_passthrough_check_and_consume_header(struct stream_buf *sb,
                                         const struct sni_pt_server_check_ctx *ctx)
{
#if defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
    msg(M_INFO, "--sni-gateway-server sni: sni_passthrough_check_and_consume_header SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif
    if (sb->buf.len >= 5)
    {
        if (BPTR(&sb->buf)[0] != 0x16) /* quick test before firing openssl on the packet */
        {
            /* client without --sni-gateway sni. */
            msg(M_INFO, "--sni-gateway-server sni: client without routing header");
            sb->sni_passthrough_state = SNI_PT_DISABLED;
            return false;
        }
        else
        {
            const uint8_t *hdr = BPTR(&sb->buf);

            int sni_total = sni_passthrough_check_packet(hdr, sb->buf.len, ctx);
            if (sni_total < 0)
            {
                /* Complete ClientHello parsed but criteria not met — reject. */
                sb->error = true;
                sb->sni_passthrough_state = SNI_PT_DISABLED;
                return false;
            }
            if (sni_total == 0)
            {
                /*
                 * The packet was not (yet) recognised as a complete SNI header.
                 * If we already have 5 bytes we know the TLS record length.
                 * Reject immediately if the record would never fit in our buffer
                 * or exceeds the TLS maximum record size — waiting longer cannot
                 * help, and leaving the connection open would fill the buffer.
                 */
                if (sb->buf.len >= 5)
                {
                    int rlen = ((int)hdr[3] << 8) | (int)hdr[4];
                    if (5 + rlen > sb->maxlen || rlen > 0x4000)
                    {
                        msg(M_WARN,
                            "--sni-gateway-server sni: oversized TLS record (%d bytes), rejecting",
                            5 + rlen);
                        sb->error = true;
                        sb->sni_passthrough_state = SNI_PT_DISABLED;
                    }
                }
                return false;
            }
            else if (sb->buf.len < sni_total)
            {
                /* Not enough data yet; should not happen. */
                msg(M_WARN, "--sni-gateway-server sni: cant discard SNI routing header %d bytes of %d buffer", sni_total, sb->buf.len);
                return false;
            }
            else
            {
                /* Full routing header received; discard it and reset the buffer so
                 * normal OpenVPN stream parsing sees a clean slate. */
                int remaining = sb->buf.len - sni_total;
                msg(M_INFO, "--sni-gateway-server sni: discarded SNI routing header %d bytes of %d buffer", sni_total, sb->buf.len);

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


#if defined(UNIT_TESTING) && !defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
/*
 * Expose the internal builder for cross-path compatibility tests.
 * Guarded by !SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH so that sni_alt_impl.c
 * (which includes this file with the alt-path define set and all public
 * symbols renamed) does not emit a conflicting definition.
 */
size_t
sni_passthrough_build_client_hello_test(uint8_t *buf, size_t bufsz,
                                        const char *sni,
                                        const char *const *alpn_list,
                                        int alpn_count)
{
    return sni_passthrough_build_client_hello(buf, bufsz, sni,
                                              alpn_list, alpn_count);
}
#endif /* UNIT_TESTING && !SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH */
