/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "dns.h"
#include "test_common.h"

/* dns.c pulls in argv.c, which needs parse_line(), it is not used here */
int
parse_line(const char *line, char **p, const int n, const char *file, const int line_num,
           msglvl_t msglevel, struct gc_arena *gc)
{
    return 0;
}

/* Numeric only, like openvpn_getaddrinfo() without GETADDR_RESOLVE */
int
openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                    int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                    struct addrinfo **res)
{
    struct addrinfo hints;
    CLEAR(hints);
    hints.ai_family = ai_family;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;
    return getaddrinfo(hostname, servname, &hints, res);
}

static void
parse(struct dns_options *o, const char *line)
{
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *p[16] = { 0 };
    int n = 0;
    for (char *t = strtok(buf, " "); t && n < 15; t = strtok(NULL, " "))
    {
        p[n++] = string_alloc(t, &o->gc);
    }
    assert_true(dns_option_parse(o, p, M_WARN, true));
}

static void
test_to_dhcp_options(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    /* server 0 uses DoT and cannot be expressed, server 1 can */
    parse(&o, "dns server 0 address 10.8.0.9");
    parse(&o, "dns server 0 transport DoT");
    parse(&o, "dns server 1 address 10.8.0.1 fd00::1");
    parse(&o, "dns server 1 resolve-domains split.example");
    parse(&o, "dns search-domains corp.example second.example");

    struct gc_arena gc = gc_new();
    const char **l = dns_options_to_dhcp_options(&o, &gc);
    assert_non_null(l);
    assert_string_equal(l[0], "dhcp-option DNS 10.8.0.1");
    assert_string_equal(l[1], "dhcp-option DNS6 fd00::1");
    assert_string_equal(l[2], "dhcp-option DOMAIN corp.example");
    assert_string_equal(l[3], "dhcp-option DOMAIN-SEARCH second.example");
    assert_null(l[4]);

    gc_free(&gc);
    gc_free(&o.gc);
}

static void
test_to_dhcp_options_none(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    parse(&o, "dns server 0 address 10.8.0.1:5353");
    parse(&o, "dns server 1 address 10.8.0.2");
    parse(&o, "dns server 1 dnssec yes");

    struct gc_arena gc = gc_new();
    assert_null(dns_options_to_dhcp_options(&o, &gc));
    gc_free(&gc);
    gc_free(&o.gc);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_to_dhcp_options),
        cmocka_unit_test(test_to_dhcp_options_none),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
