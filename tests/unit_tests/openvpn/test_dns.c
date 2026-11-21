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
test_priority_parse(void **state)
{
    long prio = 42;
    assert_true(dns_server_priority_parse(&prio, "0", true));
    assert_int_equal(prio, 0);
    assert_true(dns_server_priority_parse(&prio, "-0", true));
    assert_int_equal(prio, 0);
    assert_true(dns_server_priority_parse(&prio, "127", true));
    assert_true(dns_server_priority_parse(&prio, "-128", false));
    assert_int_equal(prio, -128);

    /* the empty string used to be accepted as 0 */
    prio = 42;
    assert_false(dns_server_priority_parse(&prio, "", true));
    assert_false(dns_server_priority_parse(&prio, "", false));
    assert_int_equal(prio, 42);

    assert_false(dns_server_priority_parse(&prio, "128", false));
    assert_false(dns_server_priority_parse(&prio, "-1", true));
    assert_false(dns_server_priority_parse(&prio, "1x", true));
    assert_false(dns_server_priority_parse(&prio, "99999999999999999999", false));
}

static void
test_addr_parse_brackets(void **state)
{
    struct dns_server s;
    struct in6_addr lo = IN6ADDR_LOOPBACK_INIT;

    /* [::1] without a port */
    CLEAR(s);
    assert_true(dns_server_addr_parse(&s, "[::1]"));
    assert_int_equal(s.addr_count, 1);
    assert_int_equal(s.addr[0].family, AF_INET6);
    assert_int_equal(s.addr[0].port, 0);
    assert_memory_equal(&s.addr[0].in.a6, &lo, sizeof(lo));

    /* [::1]:53 */
    CLEAR(s);
    assert_true(dns_server_addr_parse(&s, "[::1]:53"));
    assert_int_equal(s.addr[0].port, 53);

    /* ::1:53 is an IPv6 address without port */
    CLEAR(s);
    assert_true(dns_server_addr_parse(&s, "::1:53"));
    assert_int_equal(s.addr[0].port, 0);

    CLEAR(s);
    assert_false(dns_server_addr_parse(&s, "[::1]:"));
    assert_false(dns_server_addr_parse(&s, "[]"));
    assert_false(dns_server_addr_parse(&s, "[::1"));
    assert_false(dns_server_addr_parse(&s, "[::1]:0"));
    assert_int_equal(s.addr_count, 0);

    /* IPv4 unchanged */
    assert_true(dns_server_addr_parse(&s, "10.0.0.1:853"));
    assert_int_equal(s.addr[0].port, 853);
}

static void
test_server_remove(void **state)
{
    struct gc_arena gc = gc_new();
    struct dns_server *list = NULL;
    struct dns_server *a = dns_server_get(&list, 1, &gc);
    struct dns_server *b = dns_server_get(&list, 2, &gc);
    struct dns_server *c = dns_server_get(&list, 3, &gc);

    dns_server_remove(&list, b);
    assert_ptr_equal(list, a);
    assert_ptr_equal(a->next, c);
    dns_server_remove(&list, a);
    assert_ptr_equal(list, c);
    dns_server_remove(&list, c);
    assert_null(list);
    dns_server_remove(&list, c); /* not in the list: no-op */
    gc_free(&gc);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_priority_parse),
        cmocka_unit_test(test_addr_parse_brackets),
        cmocka_unit_test(test_server_remove),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
