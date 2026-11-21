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
test_from_dhcp_search_without_domain(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    o.from_dhcp.dns[o.from_dhcp.dns_len++] = 0x0a080001;
    o.from_dhcp.domain_search_list[o.from_dhcp.domain_search_list_len++] = "corp.example";
    o.from_dhcp.domain_search_list[o.from_dhcp.domain_search_list_len++] = "second.example";

    dns_options_from_dhcp(&o);

    /* no NULL name in front, the search domains start at the first entry */
    assert_non_null(o.search_domains);
    assert_string_equal(o.search_domains->name, "corp.example");
    assert_non_null(o.search_domains->next);
    assert_string_equal(o.search_domains->next->name, "second.example");
    assert_null(o.search_domains->next->next);

    assert_non_null(o.servers);
    assert_int_equal(o.servers->priority, 0);
    assert_int_equal(o.servers->addr_count, 1);
    assert_int_equal(o.servers->addr[0].family, AF_INET);
    assert_int_equal(ntohl(o.servers->addr[0].in.a4.s_addr), 0x0a080001);

    gc_free(&o.gc);
}

static void
test_from_dhcp_domain_and_search(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    o.from_dhcp.dns[o.from_dhcp.dns_len++] = 0x0a080001;
    o.from_dhcp.domain = "corp.example";
    o.from_dhcp.domain_search_list[o.from_dhcp.domain_search_list_len++] = "corp.example";
    o.from_dhcp.domain_search_list[o.from_dhcp.domain_search_list_len++] = "second.example";

    dns_options_from_dhcp(&o);

    /* DOMAIN first, then DOMAIN-SEARCH without the repeated DOMAIN */
    assert_string_equal(o.search_domains->name, "corp.example");
    assert_string_equal(o.search_domains->next->name, "second.example");
    assert_null(o.search_domains->next->next);

    gc_free(&o.gc);
}

static void
test_from_dhcp_domain_only(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    o.from_dhcp.dns6[o.from_dhcp.dns6_len++] = in6addr_loopback;
    o.from_dhcp.domain = "corp.example";

    dns_options_from_dhcp(&o);

    assert_string_equal(o.search_domains->name, "corp.example");
    assert_null(o.search_domains->next);
    assert_int_equal(o.servers->addr_count, 1);
    assert_int_equal(o.servers->addr[0].family, AF_INET6);

    gc_free(&o.gc);
}

static void
test_from_dhcp_no_dns(void **state)
{
    struct dns_options o;
    CLEAR(o);
    o.gc = gc_new();
    o.from_dhcp.domain = "corp.example";
    o.from_dhcp.domain_search_list[o.from_dhcp.domain_search_list_len++] = "second.example";

    dns_options_from_dhcp(&o);

    /* no DNS server: nothing is converted */
    assert_null(o.servers);
    assert_null(o.search_domains);

    gc_free(&o.gc);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_from_dhcp_search_without_domain),
        cmocka_unit_test(test_from_dhcp_domain_and_search),
        cmocka_unit_test(test_from_dhcp_domain_only),
        cmocka_unit_test(test_from_dhcp_no_dns),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
