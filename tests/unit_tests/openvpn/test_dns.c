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

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
#ifndef _WIN32
        cmocka_unit_test(test_vars_file_path),
        cmocka_unit_test(test_vars_line),
#endif
    };

    return cmocka_run_group_tests_name("dns", tests, NULL, NULL);
}
