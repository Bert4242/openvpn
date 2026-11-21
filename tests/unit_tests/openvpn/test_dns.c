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
add_server(struct dns_server **list, long priority, const char *addr, struct gc_arena *gc)
{
    struct dns_server *server = dns_server_get(list, priority, gc);
    assert_true(dns_server_addr_parse(server, addr));
    return server;
}

static void
add_domain(struct dns_domain **list, const char *name, struct gc_arena *gc)
{
    char *domains[] = { (char *)name, NULL };
    while (*list)
    {
        list = &(*list)->next;
    }
    assert_true(dns_domain_list_append(list, domains, gc));
}

static size_t
count_servers(const struct dns_server *s)
{
    size_t n = 0;
    for (; s; s = s->next)
    {
        n++;
    }
    return n;
}

static size_t
count_domains(const struct dns_domain *d)
{
    size_t n = 0;
    for (; d; d = d->next)
    {
        n++;
    }
    return n;
}

/*
 * Sets up options like they look after a pull: local server -1 and local
 * search domain merged with the pulled server 0 and pulled search domain,
 * plus the pre-pull copy like pre_connect_save() makes it.
 */
static void
setup_pulled(struct dns_options *o, struct dns_options *pre_pull, struct gc_arena *pre_gc)
{
    CLEAR(*o);
    o->gc = gc_new();
    o->updown = "/bin/custom-updown";
    o->updown_flags = DNS_UPDOWN_FORCED;
    add_server(&o->servers, -1, "192.0.2.53", &o->gc);
    add_domain(&o->search_domains, "local.example", &o->gc);

    /* What options_postprocess_mutate() / pre_connect_save() do */
    dns_options_preprocess_pull(o);
    *pre_pull = clone_dns_options(o, pre_gc);

    /* Pulled options */
    struct dns_server *s = add_server(&o->servers, 0, "10.8.0.1", &o->gc);
    for (int i = 2; i <= 5; i++)
    {
        char addr[32];
        snprintf(addr, sizeof(addr), "10.8.0.%d", i);
        assert_true(dns_server_addr_parse(s, addr));
    }
    add_domain(&o->search_domains, "pushed.example", &o->gc);
    o->from_dhcp.domain = "dhcp.example";
    o->from_dhcp.dns_len = 1;
    o->from_dhcp.dns[0] = 0x0a000001;
    dns_options_postprocess_pull(o);
    o->servers_from_dhcp = true;

    assert_int_equal(count_servers(o->servers), 2);
    assert_int_equal(count_domains(o->search_domains), 2);
}

static void
test_reset_pulled_keeps_local_options(void **state)
{
    struct gc_arena pre_gc = gc_new();
    struct dns_options o, pre_pull;
    setup_pulled(&o, &pre_pull, &pre_gc);

    dns_options_reset_pulled(&o, &pre_pull);

    /* --dns-updown and its flags are kept */
    assert_string_equal(o.updown, "/bin/custom-updown");
    assert_int_equal(o.updown_flags, DNS_UPDOWN_FORCED);

    /* --dhcp-option values are kept, they are reset separately */
    assert_string_equal(o.from_dhcp.domain, "dhcp.example");
    assert_int_equal(o.from_dhcp.dns_len, 1);
    assert_false(o.servers_from_dhcp);

    /* pulled servers are gone, local ones are back in servers_prepull */
    assert_null(o.servers);
    assert_int_equal(count_servers(o.servers_prepull), 1);
    assert_int_equal(o.servers_prepull->priority, -1);

    /* only the local search domain is left */
    assert_int_equal(count_domains(o.search_domains), 1);
    assert_string_equal(o.search_domains->name, "local.example");

    /* A new server 0 with 4 addresses must be accepted, even though the
     * replaced server 0 had 5 already (4 + 5 > 8) */
    struct dns_server *s = dns_server_get(&o.servers, 0, &o.gc);
    assert_true(dns_server_addr_parse(s, "10.8.1.1"));
    assert_true(dns_server_addr_parse(s, "10.8.1.2"));
    assert_true(dns_server_addr_parse(s, "10.8.1.3"));
    assert_true(dns_server_addr_parse(s, "10.8.1.4"));
    assert_int_equal(s->addr_count, 4);

    /* and merging brings back the local server in front */
    assert_true(dns_options_verify(M_WARN, &o));
    dns_options_postprocess_pull(&o);
    assert_int_equal(count_servers(o.servers), 2);
    assert_int_equal(o.servers->priority, -1);
    assert_int_equal(o.servers->next->priority, 0);
    assert_int_equal(o.servers->next->addr_count, 4);

    gc_free(&o.gc);
    gc_free(&pre_gc);
}

static void
test_reset_pulled_without_pre_pull(void **state)
{
    struct gc_arena pre_gc = gc_new();
    struct dns_options o, pre_pull;
    setup_pulled(&o, &pre_pull, &pre_gc);

    dns_options_reset_pulled(&o, NULL);

    assert_string_equal(o.updown, "/bin/custom-updown");
    assert_int_equal(o.updown_flags, DNS_UPDOWN_FORCED);
    assert_string_equal(o.from_dhcp.domain, "dhcp.example");
    assert_null(o.servers);
    assert_null(o.servers_prepull);
    assert_null(o.search_domains);

    gc_free(&o.gc);
    gc_free(&pre_gc);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reset_pulled_keeps_local_options),
        cmocka_unit_test(test_reset_pulled_without_pre_pull),
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
