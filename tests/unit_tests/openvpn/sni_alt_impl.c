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
 * sni_alt_impl.c – re-compilation of ps_sni.c with
 * SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH forced, exporting all public
 * symbols under distinct "_alt" names.
 *
 * This lets sni_compat_testdriver link both the normal (possibly OpenSSL)
 * and the generic byte-scan flavour of every builder/checker function into
 * a single binary without duplicate-symbol conflicts.
 *
 * Symbol mapping (via #define before #include):
 *
 *   ps_sni.c name                              alt name
 *   ─────────────────────────────────────────  ──────────────────────────────────────────────────
 *   sni_passthrough_build_client_hello         sni_passthrough_build_client_hello_alt_test_path
 *   sni_passthrough_send_client_hello          sni_passthrough_send_client_hello_alt_test_path
 *   sni_passthrough_check_packet               sni_passthrough_check_packet_alt_test_path
 *   sni_passthrough_check_and_consume_header   sni_passthrough_check_and_consume_header_alt_test_path
 *
 * After the include, a thin public wrapper exposes the renamed static
 * builder under the name used by the compatibility test:
 *
 *   sni_passthrough_build_client_hello_alt_test_path()
 */

/* Force the generic byte-scan path regardless of crypto backend. */
#define SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH

/*
 * Rename all public (non-static) symbols so this translation unit can
 * coexist with the normal ps_sni.o in the same link step.
 *
 * The static builder sni_passthrough_build_client_hello is also renamed
 * (to sni_passthrough_build_client_hello_alt_test_path) so we can wrap it below.
 */
#define sni_passthrough_build_client_hello       sni_passthrough_build_client_hello_alt_test_path
#define sni_passthrough_send_client_hello        sni_passthrough_send_client_hello_alt_test_path
#define sni_passthrough_check_packet             sni_passthrough_check_packet_alt_test_path
#define sni_passthrough_check_and_consume_header sni_passthrough_check_and_consume_header_alt_test_path

/*
 * Pull in the full ps_sni.c source.  The -I flag for src/openvpn is
 * always present in the test driver CFLAGS so the include resolves
 * correctly.  The UNIT_TESTING wrapper added to ps_sni.c is suppressed
 * by the SNI_PASSTHROUGH_TEST_ALTERNATIVE_PATH guard, so no conflicting
 * sni_passthrough_build_client_hello_test symbol is emitted here.
 */
#include "ps_sni.c"

#if SNI_PASSTHROUGH
#include <stdint.h>
#include <stddef.h>

/*
 * sni_passthrough_build_client_hello_alt_test_path is defined static inside
 * the included ps_sni.c.  Expose it under an externally-linkable name so
 * the compatibility test can call both the normal and alt builders from
 * the same test binary.
 */
size_t
sni_passthrough_build_client_hello_alt_test_path_wrapper(uint8_t *buf, size_t bufsz,
                                                         const char *sni,
                                                         const char *alpn)
{
    return sni_passthrough_build_client_hello_alt_test_path(buf, bufsz, sni, alpn);
}
#endif /* SNI_PASSTHROUGH */
