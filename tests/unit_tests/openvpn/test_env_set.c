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

#include "env_set.h"
#include "test_common.h"

/* same rule as is_dhcp_foreign_option() in options.c */
static bool
is_dhcp_fo(const char *str, void *arg)
{
    int *calls = arg;
    (*calls)++;
    const char *v = strchr(str, '=');
    return strncmp(str, "foreign_option_", 15) == 0 && v
           && strncmp(v + 1, "dhcp-option ", 12) == 0;
}

static unsigned int
count_items(const struct env_set *es)
{
    unsigned int n = 0;
    for (const struct env_item *e = es->list; e; e = e->next)
    {
        n++;
    }
    return n;
}

static void
fill(struct env_set *es)
{
    /* env items are added at the head, so the dhcp-option entries end
     * up next to each other, like after a push */
    setenv_str(es, "dev", "tun0");
    setenv_str(es, "foreign_option_1", "dhcp-option DNS 10.0.0.1");
    setenv_str(es, "foreign_option_2", "dhcp-option DOMAIN-SEARCH old.corp");
    setenv_str(es, "foreign_option_3", "dhcp-option DOMAIN old.corp");
    setenv_str(es, "foreign_option_4", "dhcp-option DNS6 fd00::1");
    setenv_str(es, "foreign_option_x", "something else");
    setenv_str(es, "ifconfig_local", "10.8.0.2");
}

static void
check_result(struct env_set *es, unsigned int removed, int calls)
{
    assert_int_equal(removed, 4);
    assert_int_equal(calls, 7);
    assert_int_equal(count_items(es), 3);
    assert_null(env_set_get(es, "foreign_option_1"));
    assert_null(env_set_get(es, "foreign_option_2"));
    assert_null(env_set_get(es, "foreign_option_3"));
    assert_null(env_set_get(es, "foreign_option_4"));
    assert_string_equal(env_set_get(es, "dev"), "dev=tun0");
    assert_string_equal(env_set_get(es, "foreign_option_x"), "foreign_option_x=something else");
    assert_string_equal(env_set_get(es, "ifconfig_local"), "ifconfig_local=10.8.0.2");
}

static void
test_env_set_del_if_malloc(void **state)
{
    /* no gc: items are malloc()ed and must be freed (checked by ASan/LSan) */
    struct env_set *es = env_set_create(NULL);
    fill(es);
    int calls = 0;
    unsigned int removed = env_set_del_if(es, is_dhcp_fo, &calls);
    check_result(es, removed, calls);

    /* nothing left to remove */
    calls = 0;
    assert_int_equal(env_set_del_if(es, is_dhcp_fo, &calls), 0);
    env_set_destroy(es);
}

static void
test_env_set_del_if_gc(void **state)
{
    struct gc_arena gc = gc_new();
    struct env_set *es = env_set_create(&gc);
    fill(es);
    int calls = 0;
    unsigned int removed = env_set_del_if(es, is_dhcp_fo, &calls);
    check_result(es, removed, calls);
    gc_free(&gc);
}

static void
test_env_set_del_if_all(void **state)
{
    struct env_set *es = env_set_create(NULL);
    setenv_str(es, "foreign_option_1", "dhcp-option DNS 10.0.0.1");
    setenv_str(es, "foreign_option_2", "dhcp-option DNS 10.0.0.2");
    int calls = 0;
    assert_int_equal(env_set_del_if(es, is_dhcp_fo, &calls), 2);
    assert_null(es->list);
    env_set_destroy(es);
}

int
main(void)
{
    openvpn_unit_test_setup();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_env_set_del_if_malloc),
        cmocka_unit_test(test_env_set_del_if_gc),
        cmocka_unit_test(test_env_set_del_if_all),
    };

    return cmocka_run_group_tests_name("env_set", tests, NULL, NULL);
}
