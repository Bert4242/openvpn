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

static struct dns_server *
make_server(const char **addrs, struct gc_arena *gc)
{
    struct dns_server *s = NULL;
    ALLOC_OBJ_CLEAR_GC(s, struct dns_server, gc);
    for (; *addrs; addrs++)
    {
        assert_true(dns_server_addr_parse(s, *addrs));
    }
    return s;
}

static void
test_addrs_copy_four_ipv4(void **state)
{
    struct gc_arena gc = gc_new();
    const char *addrs[] = { "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", NULL };
    struct dns_server *s = make_server(addrs, &gc);
    struct dhcp_options d;
    CLEAR(d);

    /* all 4 fit, nothing ends up as IPv6 */
    assert_true(dns_server_addrs_copy(s, d.dns, &d.dns_len, d.dns6, &d.dns6_len, N_DHCP_ADDR));
    assert_int_equal(d.dns_len, 4);
    assert_int_equal(d.dns6_len, 0);
    assert_int_equal(d.dns[0], 0x0a000001);
    assert_int_equal(d.dns[3], 0x0a000004);
    gc_free(&gc);
}

static void
test_addrs_copy_five_ipv4(void **state)
{
    struct gc_arena gc = gc_new();
    const char *addrs[] = { "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", NULL };
    struct dns_server *s = make_server(addrs, &gc);
    struct dhcp_options d;
    CLEAR(d);

    /* the 5th IPv4 address does not fit and must not be stored as IPv6 */
    assert_false(dns_server_addrs_copy(s, d.dns, &d.dns_len, d.dns6, &d.dns6_len, N_DHCP_ADDR));
    assert_int_equal(d.dns_len, 4);
    assert_int_equal(d.dns6_len, 0);
    gc_free(&gc);
}

static void
test_addrs_copy_mixed(void **state)
{
    struct gc_arena gc = gc_new();
    const char *addrs[] = { "10.0.0.1", "fd00::1", "10.0.0.2", "fd00::2", "fd00::3",
                            "fd00::4", "fd00::5", NULL };
    struct dns_server *s = make_server(addrs, &gc);
    struct dhcp_options d;
    CLEAR(d);

    assert_false(dns_server_addrs_copy(s, d.dns, &d.dns_len, d.dns6, &d.dns6_len, N_DHCP_ADDR));
    assert_int_equal(d.dns_len, 2);
    assert_int_equal(d.dns6_len, 4);
    struct in6_addr fd00_1;
    assert_int_equal(inet_pton(AF_INET6, "fd00::1", &fd00_1), 1);
    assert_memory_equal(&d.dns6[0], &fd00_1, sizeof(fd00_1));
    gc_free(&gc);
}

static void
test_domains_copy(void **state)
{
    struct gc_arena gc = gc_new();
    struct dns_domain *list = NULL;
    char *names[] = { "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", NULL };

    /* 10 domains: all fit */
    names[10] = NULL;
    assert_true(dns_domain_list_append(&list, names, &gc));
    struct dhcp_options d;
    CLEAR(d);
    assert_true(dns_domains_copy(list, d.domain_search_list, &d.domain_search_list_len,
                                 N_SEARCH_LIST_LEN));
    assert_int_equal(d.domain_search_list_len, N_SEARCH_LIST_LEN);
    assert_string_equal(d.domain_search_list[9], "d10");

    /* 11 domains: one does not fit */
    struct dns_domain *last = list;
    while (last->next)
    {
        last = last->next;
    }
    char *eleventh[] = { "d11", NULL };
    assert_true(dns_domain_list_append(&last->next, eleventh, &gc));
    CLEAR(d);
    assert_false(dns_domains_copy(list, d.domain_search_list, &d.domain_search_list_len,
                                  N_SEARCH_LIST_LEN));
    assert_int_equal(d.domain_search_list_len, N_SEARCH_LIST_LEN);
    gc_free(&gc);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_addrs_copy_four_ipv4),
        cmocka_unit_test(test_addrs_copy_five_ipv4),
        cmocka_unit_test(test_addrs_copy_mixed),
        cmocka_unit_test(test_domains_copy),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
