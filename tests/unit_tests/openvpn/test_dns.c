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

/* ---- from dns-fix/01 ---- */

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

/* ---- from dns-fix/03 ---- */

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

/* ---- from dns-fix/04 ---- */

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

/* ---- from dns-fix/07 ---- */

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

/* ---- from dns-fix/08 ---- */

#ifndef _WIN32
static void
test_vars_file_path(void **state)
{
    assert_true(dns_vars_file_path_valid("/tmp/openvpn_dvf_0123abcd.tmp", "/tmp"));
    assert_true(dns_vars_file_path_valid("/tmp/openvpn_dvf_0123abcd.tmp", "/tmp/"));
    assert_true(dns_vars_file_path_valid("/run/ovpn/openvpn_dvf_1.tmp", "/run/ovpn"));

    /* anything else must be refused, the runner unlinks it as root */
    assert_false(dns_vars_file_path_valid("/etc/shadow", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/../etc/openvpn_dvf_1.tmp", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/sub/openvpn_dvf_1.tmp", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmpx/openvpn_dvf_1.tmp", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/openvpn_dvr_1.tmp", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/openvpn_dvf_1.tmp.sh", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/openvpn_dvf_.tmp", "/tmp"));
    assert_false(dns_vars_file_path_valid("/tmp/openvpn_dvf_1.tmp", ""));
    assert_false(dns_vars_file_path_valid(NULL, "/tmp"));
}

static void
test_vars_line(void **state)
{
    assert_true(dns_vars_line_valid("dev=tun0"));
    assert_true(dns_vars_line_valid("script_type=dns-up"));
    assert_true(dns_vars_line_valid("dns_search_domain_1=corp.example"));
    assert_true(dns_vars_line_valid("dns_server_1_address_1=fd00::1"));
    assert_true(dns_vars_line_valid("dns_server_1_address_2=fe80::1%tun0"));
    assert_true(dns_vars_line_valid("dns_server_1_port_1=853"));
    assert_true(dns_vars_line_valid("dns_server_1_transport=DoT"));
    assert_true(dns_vars_line_valid("dns_search_domain_2=b\xc3\xbc"
                                    "cher.example"));
    assert_true(dns_vars_line_valid("dns_search_domain_3="));

    /* code injection when sourced */
    assert_false(dns_vars_line_valid("dns_search_domain_1=$(touch /tmp/x)"));
    assert_false(dns_vars_line_valid("dns_search_domain_1=`id`"));
    assert_false(dns_vars_line_valid("dns_search_domain_1=a;id"));
    assert_false(dns_vars_line_valid("dns_search_domain_1=a id"));
    assert_false(dns_vars_line_valid("dns_search_domain_1='a'"));
    assert_false(dns_vars_line_valid("dns_search_domain_1=a|id"));
    assert_false(dns_vars_line_valid("dns_search_domain_1=~root"));
    /* unexpected names */
    assert_false(dns_vars_line_valid("PATH=/tmp"));
    assert_false(dns_vars_line_valid("LD_PRELOAD=/tmp/x.so"));
    assert_false(dns_vars_line_valid("dns_=x"));
    assert_false(dns_vars_line_valid("dns_X=x"));
    assert_false(dns_vars_line_valid("=x"));
    assert_false(dns_vars_line_valid("dev"));
}
#endif

/* ---- from dns-fix/10 ---- */

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
        cmocka_unit_test(test_reset_pulled_keeps_local_options),
        cmocka_unit_test(test_reset_pulled_without_pre_pull),

        cmocka_unit_test(test_from_dhcp_search_without_domain),
        cmocka_unit_test(test_from_dhcp_domain_and_search),
        cmocka_unit_test(test_from_dhcp_domain_only),
        cmocka_unit_test(test_from_dhcp_no_dns),

        cmocka_unit_test(test_addrs_copy_four_ipv4),
        cmocka_unit_test(test_addrs_copy_five_ipv4),
        cmocka_unit_test(test_addrs_copy_mixed),
        cmocka_unit_test(test_domains_copy),

        cmocka_unit_test(test_to_dhcp_options),
        cmocka_unit_test(test_to_dhcp_options_none),

#ifndef _WIN32
        cmocka_unit_test(test_vars_file_path),
        cmocka_unit_test(test_vars_line),
#endif

        cmocka_unit_test(test_priority_parse),
        cmocka_unit_test(test_addr_parse_brackets),
        cmocka_unit_test(test_server_remove),

    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
