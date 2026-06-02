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
#include "ps_sni.h"

/*
 * SNI passthrough support
 * (--sni-passthrough-hostname / --sni-passthrough-server).
 *
 * Allows OpenVPN TCP connections to pass through SNI-aware TCP proxies such
 * as Traefik (passthrough mode) on any port, without any double encryption.
 *
 * SNI-aware proxies read the hostname from the first bytes of the TCP stream
 * and route the connection accordingly.  They expect those bytes to be
 * formatted as a ClientHello record (the standard carrier for SNI in TCP).
 *
 *   Client (--sni-passthrough-hostname <hostname>):
 *     Prepends a single SNI routing header — a ClientHello record
 *     carrying the given hostname — before the OpenVPN protocol bytes.
 *     The proxy reads the hostname, routes the stream to the right backend,
 *     and forwards all bytes (including the header) maybe unchanged.
 *
 *   Server (--sni-passthrough-server):
 *     Receives the routed stream, reads and discards the SNI routing header,
 *     then proceeds with the normal OpenVPN protocol. Openvpn clients that
 *     do not send the header are detected automatically and handled normally.
 *
 * No session of any kind is established by the routing header — it is
 * discarded immediately.  No encryption layer is added; OpenVPN's own
 * control-channel and data-channel security are used unchanged.
 */

/* Default ALPN protocol name when --sni-passthrough-alpn is not set. */
#define SNI_PT_DEFAULT_ALPN     "hacky-sni-passthrough"
#define SNI_PT_DEFAULT_ALPN_LEN 21u /* strlen("hacky-sni-passthrough") */

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
 * Write all ALPN tokens as wire-format length-prefixed entries into buf[].
 * Returns total bytes written, or 0 on overflow / bad token length.
 */
static size_t
sni_pt_build_alpn_proto_list(unsigned char *buf, size_t bufsz,
                             const char *const *alpn_list, int alpn_count)
{
    size_t off = 0;
    for (int i = 0; i < alpn_count; i++)
    {
        const char *name = alpn_list[i];
        if (!name || !*name)
        {
            continue;
        }
        size_t name_len = strlen(name);
        if (name_len > 255 || off + 1 + name_len > bufsz)
        {
            return 0;
        }
        buf[off++] = (unsigned char)name_len;
        memcpy(buf + off, name, name_len);
        off += name_len;
    }
    return off;
}

/*
 * Case-insensitive ASCII comparison of a binary buffer against a NUL-terminated
 * string.  Returns true if they are equal in length and content.
 */
static bool
sni_pt_str_eq_nocase(const unsigned char *buf, unsigned int buflen,
                     const char *str)
{
    size_t slen = strlen(str);
    if (buflen != (unsigned int)slen)
    {
        return false;
    }
    for (unsigned int i = 0; i < buflen; i++)
    {
        unsigned char a = buf[i];
        unsigned char b = (unsigned char)str[i];
        /* ASCII lower-case: A-Z → a-z */
        if (a >= 'A' && a <= 'Z')
        {
            a += 32;
        }
        if (b >= 'A' && b <= 'Z')
        {
            b += 32;
        }
        if (a != b)
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
    unsigned char alpn_wire[4096]; /* room for many tokens */
    size_t alpn_wire_len;
    const char *const *eff_list;
    int eff_count;

    if (!sni || !*sni)
    {
        return 0;
    }

    sni_pt_resolve_alpn(alpn_list, alpn_count, &eff_list, &eff_count);
    alpn_wire_len = sni_pt_build_alpn_proto_list(alpn_wire, sizeof(alpn_wire),
                                                 eff_list, eff_count);
    if (!alpn_wire_len)
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

    if (SSL_set_alpn_protos(ssl, alpn_wire, (unsigned int)alpn_wire_len) != 0)
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
            msg(M_NONFATAL, "--sni-passthrough-hostname: SSL_do_handshake failed: %s", err_buf);
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
            msg(M_NONFATAL, "--sni-passthrough-hostname: ClientHello too large: pending=%zu bufsz=%zu", pending, bufsz);
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
 * The template was captured from OpenSSL with a 21-byte hostname.
 * The prefix covers bytes [0..155] (everything up to the
 * hostname), the suffix covers bytes [177..1576] (everything after).
 * When building, we copy prefix, insert the requested hostname, append
 * suffix, then patch the five length fields that span the SNI extension
 * up to the TLS record envelope.
 *
 * Fields patched (delta = new_sni_len - 21):
 *   buf[3..4]     TLS record length        (2 bytes, +delta)
 *   buf[6..8]     Handshake message length (3 bytes, +delta)
 *   buf[140..141] Extensions total length  (2 bytes, +delta)
 *   buf[149..150] SNI ext_data_len         (2 bytes, +delta)
 *   buf[151..152] SNI server_name_list_len (2 bytes, +delta)
 *   buf[154..155] SNI name_len             (2 bytes, = new_sni_len)
 *
 * The 32-byte random field at buf[11..42] is re-randomised every call.
 */

/* clang-format off */
static const uint8_t sni_pt_prefix[156] = {
    /* TLS record header: Handshake(0x16), TLS1.0, length=1572 */
    0x16,0x03,0x01,0x06,0x24,
    /* Handshake header: ClientHello(0x01), length=1568 */
    0x01,0x00,0x06,0x20,
    /* client_version: TLS 1.2 */
    0x03,0x03,
    /* random (32 bytes) - overwritten at use time */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* session_id_len=32, session_id - overwritten at use time */
    0x20,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* cipher_suites_len=60, 30 cipher suites */
    0x00,0x3c,
    0x13,0x02,0x13,0x03,0x13,0x01,0xc0,0x2c,
    0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,
    0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e,
    0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,
    0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14,
    0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,
    0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c,
    0x00,0x35,0x00,0x2f,
    /* compression_methods: null only */
    0x01,0x00,
    /* extensions_len=1449 */
    0x05,0xa9,
    /* ext renegotiation_info (0xff01): len=1, data=0x00 */
    0xff,0x01,0x00,0x01,0x00,
    /* ext server_name (0x0000) */
    0x00,0x00,
    0x00,0x1a,  /* ext_data_len=26  [149..150] */
    0x00,0x18,  /* server_name_list_len=24  [151..152] */
    0x00,       /* name_type: host_name */
    0x00,0x15   /* name_len=21  [154..155] */
    /* hostname (21 bytes) follows at [156]  */
};

/*
 * The suffix is split into two halves around the ALPN extension, which is
 * now built dynamically so that --sni-passthrough-alpn can override it.
 *
 * sni_pt_suffix_pre_alpn  – extensions before the ALPN extension (34 bytes)
 * sni_pt_suffix_post_alpn – extensions after the ALPN extension (1352 bytes)
 *
 * The default ALPN ("hacky-sni-passthrough") is 28 bytes on the wire:
 *   ext_type(2) + ext_data_len(2) + list_len(2) + proto_len(1) + name(21)
 * So the default total suffix = 34 + 28 + 1352 = 1414 bytes, matching the
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

#define SNI_PT_PREFIX_LEN           156u
#define SNI_PT_SUFFIX_PRE_ALPN_LEN  34u
#define SNI_PT_SUFFIX_POST_ALPN_LEN 1352u
#define SNI_PT_TEMPLATE_SNI_LEN     21u                                           /* length of the hostname in the captured template */

/* Wire size of the default ALPN extension: type(2)+ext_data_len(2)+list_len(2)+proto_len(1)+name */
#define SNI_PT_DEFAULT_ALPN_EXT_LEN (2u + 2u + 2u + 1u + SNI_PT_DEFAULT_ALPN_LEN) /* 28 */

/* Offsets of ephemeral key fields within sni_pt_suffix_post_alpn[] */
#define SNI_PT_POST_ALPN_MLKEM_OFF  91u                                           /* ML-KEM key data (1216 bytes) */
#define SNI_PT_POST_ALPN_MLKEM_LEN  1216u
#define SNI_PT_POST_ALPN_X25519_OFF 1311u                                         /* x25519 key data (32 bytes) */
#define SNI_PT_POST_ALPN_X25519_LEN 32u

static size_t
sni_passthrough_build_client_hello(uint8_t *buf, size_t bufsz, const char *sni,
                                   const char *const *alpn_list, int alpn_count)
{
    size_t alpn_proto_list_len; /* total bytes for all length-prefixed tokens */
    size_t alpn_ext_len;
    size_t suffix_len;
    size_t sni_len;
    size_t total;
    int sni_delta;
    int alpn_delta;
    int delta;
    int i;
    size_t off;
    /* temporary buffer for the ALPN proto list (length-prefixed tokens) */
    unsigned char alpn_proto_buf[4096];
    const char *const *eff_list;
    int eff_count;

#if defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
    msg(M_INFO, "--sni-passthrough-hostname: sni_passthrough_build_client_hello SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif

    if (!sni || !*sni)
    {
        return 0;
    }

    sni_pt_resolve_alpn(alpn_list, alpn_count, &eff_list, &eff_count);
    alpn_proto_list_len = sni_pt_build_alpn_proto_list(alpn_proto_buf,
                                                       sizeof(alpn_proto_buf),
                                                       eff_list, eff_count);
    if (!alpn_proto_list_len)
    {
        msg(M_NONFATAL, "--sni-passthrough-alpn: ALPN token list too long or empty");
        return 0;
    }

    /*
     * Wire-size of the ALPN extension:
     *   ext_type(2) + ext_data_len(2) + proto_list_len(2) + proto_list(var)
     */
    alpn_ext_len = 2 + 2 + 2 + alpn_proto_list_len;

    suffix_len = SNI_PT_SUFFIX_PRE_ALPN_LEN + alpn_ext_len + SNI_PT_SUFFIX_POST_ALPN_LEN;
    sni_len = strlen(sni);
    total = SNI_PT_PREFIX_LEN + sni_len + suffix_len;

    if (total > bufsz || total > 0xffffU + 5)
    {
        msg(M_NONFATAL, "--sni-passthrough-hostname: SNI hostname too long");
        return 0;
    }

    /* Deltas relative to the template's default SNI and ALPN sizes.
     * SNI_PT_DEFAULT_ALPN_EXT_LEN = 2+2+2+1+21 = 28 (one default token). */
    sni_delta = (int)sni_len - (int)SNI_PT_TEMPLATE_SNI_LEN;
    alpn_delta = (int)alpn_ext_len - (int)SNI_PT_DEFAULT_ALPN_EXT_LEN;
    delta = sni_delta + alpn_delta;

    /* Assemble: prefix + hostname + pre_alpn + ALPN ext + post_alpn */
    memcpy(buf, sni_pt_prefix, SNI_PT_PREFIX_LEN);
    memcpy(buf + SNI_PT_PREFIX_LEN, sni, sni_len);
    off = SNI_PT_PREFIX_LEN + sni_len;

    memcpy(buf + off, sni_pt_suffix_pre_alpn, SNI_PT_SUFFIX_PRE_ALPN_LEN);
    off += SNI_PT_SUFFIX_PRE_ALPN_LEN;

    /* Build ALPN extension: type(0x0010) + ext_data_len + proto_list_len + protos */
    buf[off++] = 0x00;
    buf[off++] = 0x10;                                           /* ALPN ext type */
    {
        uint16_t ext_data = (uint16_t)(2 + alpn_proto_list_len); /* list_len(2) + tokens */
        buf[off++] = (uint8_t)(ext_data >> 8);
        buf[off++] = (uint8_t)(ext_data & 0xff);
        uint16_t list_len = (uint16_t)alpn_proto_list_len;
        buf[off++] = (uint8_t)(list_len >> 8);
        buf[off++] = (uint8_t)(list_len & 0xff);
        memcpy(buf + off, alpn_proto_buf, alpn_proto_list_len);
        off += alpn_proto_list_len;
    }

    memcpy(buf + off, sni_pt_suffix_post_alpn, SNI_PT_SUFFIX_POST_ALPN_LEN);

    /* Patch TLS record length [3..4] */
    uint16_t rec_len = (uint16_t)(total - 5);
    buf[3] = (uint8_t)(rec_len >> 8);
    buf[4] = (uint8_t)(rec_len & 0xff);

    /* Patch Handshake length [6..8] (3-byte big-endian) */
    uint32_t hs_len = (uint32_t)(total - 9);
    buf[6] = (uint8_t)((hs_len >> 16) & 0xff);
    buf[7] = (uint8_t)((hs_len >> 8) & 0xff);
    buf[8] = (uint8_t)(hs_len & 0xff);

    /* Patch extensions total length [140..141] */
    uint16_t ext_total = (uint16_t)(0x05a9 + delta);
    buf[140] = (uint8_t)(ext_total >> 8);
    buf[141] = (uint8_t)(ext_total & 0xff);

    /* Patch SNI ext_data_len [149..150] */
    uint16_t sni_ext_data_len = (uint16_t)(26 + sni_delta);
    buf[149] = (uint8_t)(sni_ext_data_len >> 8);
    buf[150] = (uint8_t)(sni_ext_data_len & 0xff);

    /* Patch SNI server_name_list_len [151..152] */
    uint16_t sni_list_len = (uint16_t)(24 + sni_delta);
    buf[151] = (uint8_t)(sni_list_len >> 8);
    buf[152] = (uint8_t)(sni_list_len & 0xff);

    /* Patch SNI name_len [154..155] */
    buf[154] = (uint8_t)(sni_len >> 8);
    buf[155] = (uint8_t)(sni_len & 0xff);

    /* Randomise the 32-byte random field [11..42] */
    for (i = 0; i < 32; i++)
    {
        buf[11 + i] = (uint8_t)(rand() & 0xff);
    }

    /* Randomise the 32-byte session_id [44..75] */
    for (i = 0; i < 32; i++)
    {
        buf[44 + i] = (uint8_t)(rand() & 0xff);
    }

    /* Randomise the ephemeral key shares in the post_alpn part of the suffix */
    size_t post_alpn_base = SNI_PT_PREFIX_LEN + sni_len + SNI_PT_SUFFIX_PRE_ALPN_LEN + alpn_ext_len;
    for (i = 0; i < (int)SNI_PT_POST_ALPN_MLKEM_LEN; i++)
    {
        buf[post_alpn_base + SNI_PT_POST_ALPN_MLKEM_OFF + i] = (uint8_t)(rand() & 0xff);
    }
    for (i = 0; i < (int)SNI_PT_POST_ALPN_X25519_LEN; i++)
    {
        buf[post_alpn_base + SNI_PT_POST_ALPN_X25519_OFF + i] = (uint8_t)(rand() & 0xff);
    }

    return total;
}

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */

/*
 * Client side (--sni-passthrough-hostname): send the SNI routing header,
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
        msg(M_NONFATAL, "--sni-passthrough-hostname: failed to build SNI routing header");
        goto error;
    }

    sent = 0;
    while (sent < (ssize_t)len)
    {
        ssize_t n = send(sd, (const char *)(buf + sent), (int)(len - sent), MSG_NOSIGNAL);
        if (n <= 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "--sni-passthrough-hostname: send() failed");
            goto error;
        }
        sent += n;
    }

    msg(M_INFO, "--sni-passthrough-hostname: sent SNI routing header (hostname: %s)", sni);
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
                        if (sni_pt_str_eq_nocase(p, nlen, cb->hostname_list[i]))
                        {
                            cb->hostname_matched = 1;
                            msg(M_INFO,
                                "--sni-passthrough-server: client_hello_cb: %s hostname matched",
                                cb->hostname_list[i]);
                            break;
                        }
                    }
                }
                p += nlen;
            }
        }
        /* hostname_matched stays 0 → filter fails → check_packet returns 0 */
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
                            "--sni-passthrough-server: client_hello_cb: %s ALPN matched",
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
        msg(M_WARN, "--sni-passthrough-server: BIO_ctrl_pending returned %zu > pkt_len %d",
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
            msg(M_INFO, "--sni-passthrough-server: sni_passthrough_check_packet consumed");
            return consumed;
        }
        else
        {
            msg(M_WARN, "--sni-passthrough-server: routing header found but not consumed");
            return 0;
        }
    }
    return 0;
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
    msg(M_INFO, "--sni-passthrough-server: sni_passthrough_check_packet SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif

    if (!ctx->ignore_alpn)
    {
        sni_pt_resolve_alpn(ctx->alpn_list, ctx->alpn_count,
                            &eff_alpn_list, &eff_alpn_count);
    }

/* Macro: advance cursor by n bytes, return 0 on overrun */
#define SNI_PT_ADVANCE(p, n, end) \
    do                            \
    {                             \
        if ((p) + (n) > (end))    \
        {                         \
            return 0;             \
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
    int total = 5 + record_len;
    if (total > pkt_len)
    {
        return 0;
    }

    const unsigned char *end = pkt + total;
    const unsigned char *p = pkt + 5; /* skip TLS record header */

    /* Handshake header: type(1) + 24-bit body length */
    if (p + 4 > end)
    {
        return 0;
    }
    if (p[0] != 0x01) /* ClientHello */
    {
        return 0;
    }
    p += 4;

    /* ClientHello body: client_version(2) + random(32) = 34 bytes */
    SNI_PT_ADVANCE(p, 34, end);

    /* session_id: length(1) + data */
    if (p + 1 > end)
    {
        return 0;
    }
    unsigned int sid_len = *p;
    SNI_PT_ADVANCE(p, 1 + sid_len, end);

    /* cipher_suites: length(2) + data */
    if (p + 2 > end)
    {
        return 0;
    }
    unsigned int cs_len = SNI_PT_READ16(p);
    SNI_PT_ADVANCE(p, 2 + cs_len, end);

    /* compression_methods: length(1) + data */
    if (p + 1 > end)
    {
        return 0;
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
        return 0;
    }
    unsigned int exts_len = SNI_PT_READ16(p);
    p += 2;

    const unsigned char *exts_end = p + exts_len;
    if (exts_end > end)
    {
        return 0;
    }

    const unsigned char *ep = p;
    while (ep + 4 <= exts_end)
    {
        unsigned int ext_type = SNI_PT_READ16(ep);
        unsigned int ext_len = SNI_PT_READ16(ep + 2);
        ep += 4;

        if (ep + ext_len > exts_end)
        {
            return 0;
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
                        if (sni_pt_str_eq_nocase(sp, nlen, ctx->hostname_list[i]))
                        {
                            hostname_ok = 1;
                            msg(M_INFO,
                                "--sni-passthrough-server: %s hostname matched (generic path)",
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
                            "--sni-passthrough-server: %s ALPN matched (generic path)",
                            exp);
                        break;
                    }
                }
                ap += name_len;
            }

            if (!alpn_ok)
            {
                /* ALPN extension present but no token matched */
                return 0;
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
    return 0;
}

#endif /* ENABLE_CRYPTO_OPENSSL && !LIBRESSL_VERSION_NUMBER */


/*
 * Server side (--sni-passthrough-server): detect and consume the SNI routing
 * header prepended by --sni-passthrough-hostname clients before the OpenVPN
 * stream begins.
 */
bool
sni_passthrough_check_and_consume_header(struct stream_buf *sb,
                                         const struct sni_pt_server_check_ctx *ctx)
{
#if defined(SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH)
    msg(M_INFO, "--sni-passthrough-server: sni_passthrough_check_and_consume_header SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH");
#endif
    if (sb->buf.len >= 5)
    {
        if (BPTR(&sb->buf)[0] != 0x16) /* quick test before firing openssl on the packet */
        {
            /* client without --sni-passthrough-hostname. */
            msg(M_INFO, "--sni-passthrough-server: client without routing header");
            sb->sni_passthrough_state = SNI_PT_DISABLED;
            return false;
        }
        else
        {
            const uint8_t *hdr = BPTR(&sb->buf);

            int sni_total = sni_passthrough_check_packet(hdr, sb->buf.len, ctx);
            if (sni_total == 0)
            {
                /* nothing found */
                return false;
            }
            else if (sb->buf.len < sni_total)
            {
                /* Not enough data yet; should not happen. */
                msg(M_WARN, "--sni-passthrough-server: cant discard SNI routing header %d bytes of %d buffer", sni_total, sb->buf.len);
                return false;
            }
            else
            {
                /* Full routing header received; discard it and reset the buffer so
                 * normal OpenVPN stream parsing sees a clean slate. */
                int remaining = sb->buf.len - sni_total;
                msg(M_INFO, "--sni-passthrough-server: discarded SNI routing header %d bytes of %d buffer", sni_total, sb->buf.len);

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
