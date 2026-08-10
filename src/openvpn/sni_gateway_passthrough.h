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

#ifndef SNI_GATEWAY_PASSTHROUGH_H
#define SNI_GATEWAY_PASSTHROUGH_H


#include "socket.h"

/*
 * Implementation of the --sni-gateway "sni" mode (SNI_GW_DROP): a fake
 * ClientHello is sent/consumed and then discarded, no real TLS added.
 * The shared mode enum and CLI string parser live in sni_gateway.h, not
 * here -- this file only needs its own mode's declarations.
 */

/*
 * Context for the server-side checker.
 *
 * ALPN matching:
 *   ignore_alpn == true  → accept any ClientHello regardless of ALPN presence
 *                          or content.  alpn_list / alpn_count are ignored.
 *   ignore_alpn == false → at least one token in the ClientHello's ALPN
 *                          extension must match one of alpn_list[].
 *                          If alpn_count == 0 the built-in default
 *                          "hacky-sni-passthrough/1" is used.
 *
 * Hostname matching:
 *   hostname_count == 0  → accept any SNI hostname (or no SNI at all).
 *   hostname_count  > 0  → the SNI extension must be present and the hostname
 *                          must match one of hostname_list[] (case-insensitive).
 */
struct sni_pt_server_check_ctx
{
    const char *const *alpn_list;
    int alpn_count;
    bool ignore_alpn;

    const char *const *hostname_list;
    int hostname_count;
};

/*
 * Client side: build and send an SNI routing header ClientHello
 * on the given connected TCP socket before the OpenVPN stream begins.
 *
 * alpn_list / alpn_count: the ALPN tokens to advertise.  When alpn_count
 * is 0 (or alpn_list is NULL), the built-in default "hacky-sni-passthrough/1"
 * is used.
 *
 * Returns true on success, false on failure.
 */
bool sni_passthrough_send_client_hello(socket_descriptor_t sd, const char *sni,
                                       const char *const *alpn_list,
                                       int alpn_count);

/*
 * Server side: drive the state machine that detects and discards the SNI
 * routing header prepended by --sni-passthrough-hostname clients.
 *
 * Returns true  — header consumed (or not present); caller continues normally.
 * Returns false — need more data, or a fatal error (sb->error set).
 */
bool sni_passthrough_check_and_consume_header(struct stream_buf *sb,
                                              const struct sni_pt_server_check_ctx *ctx);

/*
 * Inspect a raw packet against the server check context.
 * Returns the total byte length of the SNI header on match, 0 otherwise.
 * Exposed here for unit testing.
 */
int sni_passthrough_check_packet(const unsigned char *pkt, int pkt_len,
                                 const struct sni_pt_server_check_ctx *ctx);

#ifdef UNIT_TESTING
/*
 * Thin wrapper around the internal sni_passthrough_build_client_hello()
 * for cross-path compatibility tests.  Only compiled when UNIT_TESTING is
 * defined and SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH is NOT set (so the
 * normal/OpenSSL builder is exposed; sni_alt_impl.c provides the alt
 * flavour under a separate name).
 */
size_t sni_passthrough_build_client_hello_test(uint8_t *buf, size_t bufsz,
                                               const char *sni,
                                               const char *const *alpn_list,
                                               int alpn_count);
#endif /* UNIT_TESTING */


#endif /* SNI_GATEWAY_PASSTHROUGH_H */
