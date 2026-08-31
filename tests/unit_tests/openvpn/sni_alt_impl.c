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
 * sni_alt_impl.c – re-compilation of sni_gateway_passthrough.c with
 * SNI_GW_PASSTHROUGH_TEST_ALTERNATIVE_PATH forced, exporting all public
 * symbols under distinct "_alt" names.
 *
 * This lets sni_compat_testdriver link both the normal (possibly OpenSSL)
 * and the generic byte-scan flavour of every builder/checker function into
 * a single binary without duplicate-symbol conflicts.
 *
 * Symbol mapping (via #define before #include):
 *
 *   sni_gateway_passthrough.c name             alt name
 *   ─────────────────────────────────────────  ──────────────────────────────────────────────────
 *   sni_gw_passthrough_build_client_hello         sni_gw_passthrough_build_client_hello_alt_test_path
 *   sni_gw_passthrough_send_client_hello          sni_gw_passthrough_send_client_hello_alt_test_path
 *   sni_gw_passthrough_check_packet               sni_gw_passthrough_check_packet_alt_test_path
 *   sni_gw_passthrough_check_and_consume_header   sni_gw_passthrough_check_and_consume_header_alt_test_path
 *
 * After the include, a thin public wrapper exposes the renamed static
 * builder under the name used by the compatibility test:
 *
 *   sni_gw_passthrough_build_client_hello_alt_test_path()
 */

/* Force the generic byte-scan path regardless of crypto backend. */
#define SNI_GW_PASSTHROUGH_TEST_ALTERNATIVE_PATH

/*
 * Rename all public (non-static) symbols so this translation unit can
 * coexist with the normal sni_gw_passthrough.o in the same link step.
 *
 * The static builder sni_gw_passthrough_build_client_hello is also renamed
 * (to sni_gw_passthrough_build_client_hello_alt_test_path) so we can wrap it below.
 */
#define sni_gw_passthrough_build_client_hello       sni_gw_passthrough_build_client_hello_alt_test_path
#define sni_gw_passthrough_send_client_hello        sni_gw_passthrough_send_client_hello_alt_test_path
#define sni_gw_passthrough_check_packet             sni_gw_passthrough_check_packet_alt_test_path
#define sni_gw_passthrough_check_and_consume_header sni_gw_passthrough_check_and_consume_header_alt_test_path

/*
 * Pull in the full sni_gateway_passthrough.c source.  The -I flag for
 * src/openvpn is always present in the test driver CFLAGS so the include
 * resolves correctly.  The UNIT_TESTING wrapper added to
 * sni_gateway_passthrough.c is suppressed by the
 * SNI_GW_PASSTHROUGH_TEST_ALTERNATIVE_PATH guard, so no conflicting
 * sni_gw_passthrough_build_client_hello_test symbol is emitted here.
 */
#include "sni_gateway_passthrough.c"

#include <stdint.h>
#include <stddef.h>

/*
 * sni_gw_passthrough_build_client_hello_alt_test_path is defined static inside
 * the included sni_gateway_passthrough.c.  Expose it under an
 * externally-linkable name so the compatibility test can call both the
 * normal and alt builders from the same test binary.
 */
size_t
sni_gw_passthrough_build_client_hello_alt_test_path_wrapper(uint8_t *buf, size_t bufsz,
                                                            const char *sni,
                                                            const char *const *alpn_list,
                                                            int alpn_count)
{
    return sni_gw_passthrough_build_client_hello_alt_test_path(buf, bufsz, sni,
                                                               alpn_list, alpn_count);
}
