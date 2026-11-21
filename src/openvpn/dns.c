/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2026 OpenVPN Inc <sales@openvpn.net>
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

#include "dns.h"
#include "resolve.h"
#include "options.h"
#include "run_command.h"
#include "domain_helper.h"

#ifdef _WIN32
#include "win32.h"
#include "openvpn-msg.h"
#endif

/**
 * Parses a string as port and stores it
 *
 * @param   port        Pointer to in_port_t where the port value is stored
 * @param   port_str    Port number as string
 * @return              True if parsing was successful
 */
static bool
dns_server_port_parse(in_port_t *port, const char *port_str)
{
    char *endptr;
    errno = 0;
    unsigned long tmp = strtoul(port_str, &endptr, 10);
    if (errno || *endptr != '\0' || tmp == 0 || tmp > UINT16_MAX)
    {
        return false;
    }
    *port = (in_port_t)tmp;
    return true;
}

bool
dns_server_addr_parse(struct dns_server *server, const char *addr)
{
    if (!addr)
    {
        return false;
    }

    char addrcopy[INET6_ADDRSTRLEN] = { 0 };
    size_t copylen = 0;
    in_port_t port = 0;
    sa_family_t af;

    const char *first_colon = strchr(addr, ':');
    const char *last_colon = strrchr(addr, ':');

    if (!first_colon || first_colon == last_colon)
    {
        /* IPv4 address with optional port, e.g. 1.2.3.4 or 1.2.3.4:853 */
        if (last_colon)
        {
            if (last_colon == addr || !dns_server_port_parse(&port, last_colon + 1))
            {
                return false;
            }
            copylen = first_colon - addr;
        }
        af = AF_INET;
    }
    else
    {
        /* IPv6 address with optional port, e.g. ab::cd or [ab::cd]:853 */
        if (addr[0] == '[')
        {
            addr += 1;
            const char *bracket = last_colon - 1;
            if (*bracket != ']' || bracket == addr || !dns_server_port_parse(&port, last_colon + 1))
            {
                return false;
            }
            copylen = bracket - addr;
        }
        af = AF_INET6;
    }

    /* Copy the address part into a temporary buffer and use that */
    if (copylen)
    {
        if (copylen >= sizeof(addrcopy))
        {
            return false;
        }
        memcpy(addrcopy, addr, copylen);
        addr = addrcopy;
    }

    if (server->addr_count >= SIZE(server->addr))
    {
        return false;
    }

    struct addrinfo *ai = NULL;
    if (openvpn_getaddrinfo(0, addr, NULL, 0, NULL, af, &ai) != 0)
    {
        return false;
    }

    if (ai->ai_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        server->addr[server->addr_count].in.a4.s_addr = sin->sin_addr.s_addr;
    }
    else
    {
        const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
        server->addr[server->addr_count].in.a6 = sin6->sin6_addr;
    }

    server->addr[server->addr_count].family = af;
    server->addr[server->addr_count].port = port;
    server->addr_count += 1;

    freeaddrinfo(ai);
    return true;
}

bool
dns_domain_list_append(struct dns_domain **entry, char **domains, struct gc_arena *gc)
{
    /* Fast forward to the end of the list */
    while (*entry)
    {
        entry = &((*entry)->next);
    }

    /* Append all domains to the end of the list */
    while (*domains)
    {
        const char *domain = *domains++;
        if (!validate_domain(domain))
        {
            return false;
        }

        ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, gc);
        struct dns_domain *new = *entry;
        new->name = domain;
        entry = &new->next;
    }

    return true;
}

bool
dns_server_priority_parse(long *priority, const char *str, bool pulled)
{
    char *endptr;
    const long min = pulled ? 0 : INT8_MIN;
    const long max = INT8_MAX;
    long prio = strtol(str, &endptr, 10);
    if (*endptr != '\0' || prio < min || prio > max)
    {
        return false;
    }
    *priority = prio;
    return true;
}

bool
dns_option_parse(struct dns_options *o, char *p[], const msglvl_t msglevel, bool pulled)
{
    if (streq(p[1], "search-domains") && p[2])
    {
        if (!dns_domain_list_append(&o->search_domains, &p[2],
                                    &o->gc))
        {
            msg(msglevel, "--dns %s contain invalid characters", p[1]);
            return false;
        }
    }
    else if (streq(p[1], "server") && p[2] && p[3] && p[4])
    {
        long priority;
        if (!dns_server_priority_parse(&priority, p[2], pulled))
        {
            msg(msglevel, "--dns server: invalid priority value '%s'", p[2]);
            return false;
        }

        struct dns_server *server =
            dns_server_get(&o->servers, priority, &o->gc);

        if (streq(p[3], "address"))
        {
            for (int i = 4; p[i]; ++i)
            {
                if (!dns_server_addr_parse(server, p[i]))
                {
                    msg(msglevel, "--dns server %ld: malformed address or maximum exceeded '%s'",
                        priority, p[i]);
                    return false;
                }
            }
        }
        else if (streq(p[3], "resolve-domains"))
        {
            if (!dns_domain_list_append(&server->domains, &p[4], &o->gc))
            {
                msg(msglevel, "--dns server %ld: %s contain invalid characters", priority, p[3]);
                return false;
            }
        }
        else if (streq(p[3], "dnssec") && !p[5])
        {
            if (streq(p[4], "yes"))
            {
                server->dnssec = DNS_SECURITY_YES;
            }
            else if (streq(p[4], "no"))
            {
                server->dnssec = DNS_SECURITY_NO;
            }
            else if (streq(p[4], "optional"))
            {
                server->dnssec = DNS_SECURITY_OPTIONAL;
            }
            else
            {
                msg(msglevel, "--dns server %ld: malformed dnssec value '%s'", priority, p[4]);
                return false;
            }
        }
        else if (streq(p[3], "transport") && !p[5])
        {
            if (streq(p[4], "plain"))
            {
                server->transport = DNS_TRANSPORT_PLAIN;
            }
            else if (streq(p[4], "DoH"))
            {
                server->transport = DNS_TRANSPORT_HTTPS;
            }
            else if (streq(p[4], "DoT"))
            {
                server->transport = DNS_TRANSPORT_TLS;
            }
            else
            {
                msg(msglevel, "--dns server %ld: malformed transport value '%s'", priority, p[4]);
                return false;
            }
        }
        else if (streq(p[3], "sni") && !p[5])
        {
            if (!validate_domain(p[4]))
            {
                msg(msglevel, "--dns server %ld: %s contains invalid characters", priority, p[3]);
                return false;
            }
            server->sni = p[4];
        }
        else
        {
            msg(msglevel,
                "--dns server %ld: unknown option type '%s' or missing or unknown parameter",
                priority, p[3]);
            return false;
        }
    }
    else
    {
        msg(msglevel, "--dns: unknown option type '%s' or missing or unknown parameter", p[1]);
        return false;
    }
    return true;
}

struct dns_server *
dns_server_get(struct dns_server **entry, long priority, struct gc_arena *gc)
{
    struct dns_server *obj = *entry;
    while (true)
    {
        if (!obj || obj->priority > priority)
        {
            ALLOC_OBJ_CLEAR_GC(*entry, struct dns_server, gc);
            (*entry)->next = obj;
            (*entry)->priority = priority;
            return *entry;
        }
        else if (obj->priority == priority)
        {
            return obj;
        }
        entry = &obj->next;
        obj = *entry;
    }
}

bool
dns_options_verify(msglvl_t msglevel, const struct dns_options *o)
{
    const struct dns_server *server = o->servers ? o->servers : o->servers_prepull;
    while (server)
    {
        if (server->addr_count == 0)
        {
            msg(msglevel, "ERROR: dns server %ld does not have an address assigned",
                server->priority);
            return false;
        }
        server = server->next;
    }
    return true;
}

static struct dns_domain *
clone_dns_domains(const struct dns_domain *domain, struct gc_arena *gc)
{
    struct dns_domain *new_list = NULL;
    struct dns_domain **new_entry = &new_list;

    while (domain)
    {
        ALLOC_OBJ_CLEAR_GC(*new_entry, struct dns_domain, gc);
        struct dns_domain *new_domain = *new_entry;
        *new_domain = *domain;
        new_entry = &new_domain->next;
        domain = domain->next;
    }

    return new_list;
}

static struct dns_server *
clone_dns_servers(const struct dns_server *server, struct gc_arena *gc)
{
    struct dns_server *new_list = NULL;
    struct dns_server **new_entry = &new_list;

    while (server)
    {
        ALLOC_OBJ_CLEAR_GC(*new_entry, struct dns_server, gc);
        struct dns_server *new_server = *new_entry;
        *new_server = *server;
        new_server->domains = clone_dns_domains(server->domains, gc);
        new_entry = &new_server->next;
        server = server->next;
    }

    return new_list;
}

struct dns_options
clone_dns_options(const struct dns_options *o, struct gc_arena *gc)
{
    struct dns_options clone;

    memset(&clone, 0, sizeof(clone));
    clone.search_domains = clone_dns_domains(o->search_domains, gc);
    clone.servers = clone_dns_servers(o->servers, gc);
    clone.servers_prepull = clone_dns_servers(o->servers_prepull, gc);
    clone.updown = o->updown;
    clone.updown_flags = o->updown_flags;
    clone.from_dhcp = o->from_dhcp;

    return clone;
}

void
dns_options_preprocess_pull(struct dns_options *o)
{
    o->servers_prepull = o->servers;
    o->servers = NULL;
}

bool
dns_domains_copy(const struct dns_domain *d, const char **list, unsigned int *len,
                 const unsigned int max_len)
{
    while (d && *len < max_len)
    {
        list[(*len)++] = d->name;
        d = d->next;
    }
    return d == NULL;
}

bool
dns_server_addrs_copy(const struct dns_server *s, in_addr_t *dns, unsigned int *dns_len,
                      struct in6_addr *dns6, unsigned int *dns6_len, const unsigned int max_len)
{
    bool all_copied = true;
    for (size_t i = 0; i < s->addr_count; ++i)
    {
        if (s->addr[i].family == AF_INET)
        {
            if (*dns_len < max_len)
            {
                dns[(*dns_len)++] = ntohl(s->addr[i].in.a4.s_addr);
            }
            else
            {
                all_copied = false;
            }
        }
        else
        {
            if (*dns6_len < max_len)
            {
                dns6[(*dns6_len)++] = s->addr[i].in.a6;
            }
            else
            {
                all_copied = false;
            }
        }
    }
    return all_copied;
}

void
dns_options_reset_pulled(struct dns_options *o, const struct dns_options *pre_pull)
{
    const char *updown = o->updown;
    const enum dns_updown_flags updown_flags = o->updown_flags;
    const struct dhcp_options from_dhcp = o->from_dhcp;
    struct gc_arena old_gc = o->gc;
    struct gc_arena gc = gc_new();

    if (pre_pull)
    {
        /* Local servers are in servers_prepull, local search domains in
         * search_domains. Pulled servers are expected in servers, see
         * dns_options_postprocess_pull(). */
        *o = clone_dns_options(pre_pull, &gc);
        o->servers = NULL;
    }
    else
    {
        CLEAR(*o);
    }

    o->updown = updown;
    o->updown_flags = updown_flags;
    o->from_dhcp = from_dhcp;
    o->servers_from_dhcp = false;
    o->gc = gc;

    /* Free only now, the clone above does not reference the old arena */
    gc_free(&old_gc);
}

void
dns_options_from_dhcp(struct dns_options *o)
{
    const struct dhcp_options *dhcp = &o->from_dhcp;

    if (!dhcp->dns_len && !dhcp->dns6_len)
    {
        return;
    }

    /* DOMAIN first, if there is one, then the DOMAIN-SEARCH list */
    struct dns_domain **entry = &o->search_domains;
    if (dhcp->domain)
    {
        ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, &o->gc);
        struct dns_domain *domain = *entry;
        domain->name = dhcp->domain;
        entry = &domain->next;
    }

    for (unsigned int i = 0; i < dhcp->domain_search_list_len; ++i)
    {
        if (dhcp->domain && streq(dhcp->domain, dhcp->domain_search_list[i]))
        {
            /* already added as DOMAIN */
            continue;
        }
        ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, &o->gc);
        struct dns_domain *search_domain = *entry;
        search_domain->name = dhcp->domain_search_list[i];
        entry = &search_domain->next;
    }

    struct dns_server *server = dns_server_get(&o->servers, 0, &o->gc);
    const size_t max_addrs = SIZE(server->addr);
    o->servers_from_dhcp = true;
    for (unsigned int i = 0; i < dhcp->dns_len && server->addr_count < max_addrs; ++i)
    {
        server->addr[server->addr_count].in.a4.s_addr = htonl(dhcp->dns[i]);
        server->addr[server->addr_count].family = AF_INET;
        server->addr_count += 1;
    }
    for (unsigned int i = 0; i < dhcp->dns6_len && server->addr_count < max_addrs; ++i)
    {
        server->addr[server->addr_count].in.a6 = dhcp->dns6[i];
        server->addr[server->addr_count].family = AF_INET6;
        server->addr_count += 1;
    }
}

const char **
dns_options_to_dhcp_options(const struct dns_options *o, struct gc_arena *gc)
{
    /* first server that a plain --dhcp-option DNS/DNS6 can express */
    const struct dns_server *s = o->servers;
    for (; s; s = s->next)
    {
        bool standard_port = true;
        for (size_t i = 0; i < s->addr_count; ++i)
        {
            if (s->addr[i].port && s->addr[i].port != 53)
            {
                standard_port = false;
            }
        }
        if ((s->transport == DNS_TRANSPORT_UNSET || s->transport == DNS_TRANSPORT_PLAIN)
            && (s->dnssec == DNS_SECURITY_UNSET || s->dnssec == DNS_SECURITY_NO)
            && standard_port)
        {
            break;
        }
    }
    if (!s)
    {
        return NULL;
    }

    size_t n = s->addr_count;
    for (const struct dns_domain *d = o->search_domains; d; d = d->next)
    {
        n++;
    }

    const char **list;
    ALLOC_ARRAY_CLEAR_GC(list, const char *, n + 1, gc);
    size_t i = 0;

    for (size_t j = 0; j < s->addr_count; ++j)
    {
        struct buffer b = alloc_buf_gc(80, gc);
        if (s->addr[j].family == AF_INET)
        {
            buf_printf(&b, "dhcp-option DNS %s",
                       print_in_addr_t(s->addr[j].in.a4.s_addr, IA_NET_ORDER, gc));
        }
        else
        {
            buf_printf(&b, "dhcp-option DNS6 %s", print_in6_addr(s->addr[j].in.a6, 0, gc));
        }
        list[i++] = BSTR(&b);
    }

    /* The first search domain doubles as the connection suffix. Older
     * clients and scripts know DOMAIN, newer ones also DOMAIN-SEARCH. */
    bool first = true;
    for (const struct dns_domain *d = o->search_domains; d; d = d->next)
    {
        struct buffer b = alloc_buf_gc(strlen(d->name) + 32, gc);
        buf_printf(&b, "dhcp-option %s %s", first ? "DOMAIN" : "DOMAIN-SEARCH", d->name);
        list[i++] = BSTR(&b);
        first = false;
    }

    return list;
}

void
dns_options_postprocess_pull(struct dns_options *o)
{
    struct dns_server **entry = &o->servers;
    struct dns_server *server = *entry;
    struct dns_server *server_pp = o->servers_prepull;

    while (server && server_pp)
    {
        if (server->priority > server_pp->priority)
        {
            /* Merge static server in front of pulled one */
            struct dns_server *next_pp = server_pp->next;
            server_pp->next = server;
            *entry = server_pp;
            server = *entry;
            server_pp = next_pp;
        }
        else if (server->priority == server_pp->priority)
        {
            /* Pulled server overrides static one */
            server_pp = server_pp->next;
        }
        entry = &server->next;
        server = *entry;
    }

    /* Append remaining local servers */
    if (server_pp)
    {
        *entry = server_pp;
    }

    o->servers_prepull = NULL;
}

static const char *
dnssec_value(const enum dns_security dnssec)
{
    switch (dnssec)
    {
        case DNS_SECURITY_YES:
            return "yes";

        case DNS_SECURITY_OPTIONAL:
            return "optional";

        case DNS_SECURITY_NO:
            return "no";

        default:
            return "unset";
    }
}

static const char *
transport_value(const enum dns_server_transport transport)
{
    switch (transport)
    {
        case DNS_TRANSPORT_HTTPS:
            return "DoH";

        case DNS_TRANSPORT_TLS:
            return "DoT";

        case DNS_TRANSPORT_PLAIN:
            return "plain";

        default:
            return "unset";
    }
}

#ifdef _WIN32

static void
make_domain_list(const char *what, const struct dns_domain *src, bool nrpt_domains, char *dst,
                 size_t dst_size)
{
    /* NRPT domains need two \0 at the end for REG_MULTI_SZ
     * and a leading '.' added in front of the domain name */
    size_t term_size = nrpt_domains ? 2 : 1;
    size_t leading_dot = nrpt_domains ? 1 : 0;
    size_t offset = 0;

    memset(dst, 0, dst_size);

    while (src)
    {
        size_t len = strlen(src->name);
        if (offset + leading_dot + len + term_size > dst_size)
        {
            msg(M_WARN, "WARNING: %s truncated", what);
            if (offset)
            {
                /* Remove trailing comma */
                *(dst + offset - 1) = '\0';
            }
            break;
        }

        if (leading_dot)
        {
            *(dst + offset++) = '.';
        }
        memcpy(dst + offset, src->name, len);
        offset += len;

        src = src->next;
        if (src)
        {
            *(dst + offset++) = ',';
        }
    }
}

static void
run_up_down_service(bool add, const struct options *o, const struct dns_options *dns,
                    const struct tuntap *tt)
{
    const struct dns_server *server = dns->servers;
    const struct dns_domain *search_domains = dns->search_domains;

    while (true)
    {
        if (!server)
        {
            if (add)
            {
                msg(M_WARN, "WARNING: setting DNS failed, no compatible server profile");
            }
            return;
        }

        bool only_standard_server_ports = true;
        for (size_t i = 0; i < NRPT_ADDR_NUM; ++i)
        {
            if (server->addr[i].port && server->addr[i].port != 53)
            {
                only_standard_server_ports = false;
                break;
            }
        }
        if ((server->transport == DNS_TRANSPORT_UNSET || server->transport == DNS_TRANSPORT_PLAIN)
            && only_standard_server_ports)
        {
            break; /* found compatible server */
        }

        server = server->next;
    }

    ack_message_t ack;
    nrpt_dns_cfg_message_t nrpt = {
        .header = { (add ? msg_add_nrpt_cfg : msg_del_nrpt_cfg), sizeof(nrpt_dns_cfg_message_t),
                    0 },
        .iface = { .index = tt->adapter_index, .name = "" },
        .flags = server->dnssec == DNS_SECURITY_YES ? nrpt_dnssec : 0,
    };
    strlcpy(nrpt.iface.name, tt->actual_name, sizeof(nrpt.iface.name));

    for (size_t i = 0; i < NRPT_ADDR_NUM; ++i)
    {
        if (server->addr[i].family == AF_UNSPEC)
        {
            /* No more addresses */
            break;
        }

        if (inet_ntop(server->addr[i].family, &server->addr[i].in, nrpt.addresses[i],
                      NRPT_ADDR_SIZE)
            == NULL)
        {
            msg(M_WARN, "WARNING: could not convert dns server address");
        }
    }

    make_domain_list("dns server resolve domains", server->domains, true, nrpt.resolve_domains,
                     sizeof(nrpt.resolve_domains));

    make_domain_list("dns search domains", search_domains, false, nrpt.search_domains,
                     sizeof(nrpt.search_domains));

    msg(D_LOW, "%s NRPT DNS%s%s on '%s' (if_index = %lu) using service",
        (add ? "Setting" : "Deleting"), nrpt.resolve_domains[0] != 0 ? ", resolve domains" : "",
        nrpt.search_domains[0] != 0 ? ", search domains" : "",
        nrpt.iface.name, nrpt.iface.index);

    send_msg_iservice(o->msg_channel, &nrpt, sizeof(nrpt), &ack, "DNS");
}

#else  /* ifdef _WIN32 */

static void
setenv_dns_option(struct env_set *es, const char *format, size_t i, size_t j, const char *value)
{
    char name[64];
    bool name_ok = false;

    if (j == 0)
    {
        name_ok = checked_snprintf(name, sizeof(name), format, i);
    }
    else
    {
        name_ok = checked_snprintf(name, sizeof(name), format, i, j);
    }

    if (!name_ok)
    {
        msg(M_WARN, "WARNING: dns option setenv name buffer overflow");
    }

    setenv_str(es, name, value);
}

static void
setenv_dns_options(const struct dns_options *o, struct env_set *es)
{
    struct gc_arena gc = gc_new();
    const struct dns_server *s;
    const struct dns_domain *d;
    size_t i, j;

    for (i = 1, d = o->search_domains; d != NULL; i++, d = d->next)
    {
        setenv_dns_option(es, "dns_search_domain_%zu", i, 0, d->name);
    }

    for (i = 1, s = o->servers; s != NULL; i++, s = s->next)
    {
        for (j = 0; j < s->addr_count; ++j)
        {
            if (s->addr[j].family == AF_INET)
            {
                setenv_dns_option(es, "dns_server_%zu_address_%zu", i, j + 1,
                                  print_in_addr_t(s->addr[j].in.a4.s_addr, IA_NET_ORDER, &gc));
            }
            else
            {
                setenv_dns_option(es, "dns_server_%zu_address_%zu", i, j + 1,
                                  print_in6_addr(s->addr[j].in.a6, 0, &gc));
            }
            if (s->addr[j].port)
            {
                setenv_dns_option(es, "dns_server_%zu_port_%zu", i, j + 1,
                                  print_in_port_t(s->addr[j].port, &gc));
            }
        }

        if (s->domains)
        {
            for (j = 1, d = s->domains; d != NULL; j++, d = d->next)
            {
                setenv_dns_option(es, "dns_server_%zu_resolve_domain_%zu", i, j, d->name);
            }
        }

        if (s->dnssec)
        {
            setenv_dns_option(es, "dns_server_%zu_dnssec", i, 0, dnssec_value(s->dnssec));
        }

        if (s->transport)
        {
            setenv_dns_option(es, "dns_server_%zu_transport", i, 0, transport_value(s->transport));
        }
        if (s->sni)
        {
            setenv_dns_option(es, "dns_server_%zu_sni", i, 0, s->sni);
        }
    }

    gc_free(&gc);
}

static void
updown_env_set(bool up, const struct dns_options *o, const struct tuntap *tt, struct env_set *es)
{
    setenv_str(es, "dev", tt->actual_name);
    setenv_str(es, "script_type", up ? "dns-up" : "dns-down");
    setenv_dns_options(o, es);
}

static int
do_run_up_down_command(bool up, const char *vars_file, const struct dns_options *o,
                       const struct tuntap *tt)
{
    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();
    struct env_set *es = env_set_create(&gc);

    if (vars_file)
    {
        setenv_str(es, "dns_vars_file", vars_file);
    }
    else
    {
        updown_env_set(up, o, tt, es);
    }

    argv_printf(&argv, "%s", o->updown);
    argv_msg(M_INFO, &argv);
    int res;
    if (dns_updown_user_set(o))
    {
        res = openvpn_run_script(&argv, es, S_EXITCODE, "dns updown");
    }
    else
    {
        res = openvpn_execve_check(&argv, es, S_EXITCODE, "WARNING: Failed running dns updown");
    }
    argv_free(&argv);
    gc_free(&gc);
    return res;
}

static bool
run_updown_runner(bool up, const struct dns_options *dns, const struct tuntap *tt,
                  struct dns_updown_runner_info *updown_runner)
{
    int dns_pipe_fd[2];
    int ack_pipe_fd[2];
    if (pipe(dns_pipe_fd) != 0 || pipe(ack_pipe_fd) != 0)
    {
        msg(M_WARN | M_ERRNO, "run_dns_up_down: unable to create pipes");
        return false;
    }
    updown_runner->pid = fork();
    if (updown_runner->pid == -1)
    {
        msg(M_WARN | M_ERRNO, "run_dns_up_down: unable to fork");
        close(dns_pipe_fd[0]);
        close(dns_pipe_fd[1]);
        close(ack_pipe_fd[0]);
        close(ack_pipe_fd[1]);
        return false;
    }
    else if (updown_runner->pid > 0)
    {
        /* Parent process */
        close(dns_pipe_fd[0]);
        close(ack_pipe_fd[1]);
        updown_runner->fds[0] = ack_pipe_fd[0];
        updown_runner->fds[1] = dns_pipe_fd[1];
    }
    else
    {
        /* Script runner process, close unused FDs */
        for (int fd = 3; fd < 100; ++fd)
        {
            if (fd != dns_pipe_fd[0] && fd != ack_pipe_fd[1])
            {
                close(fd);
            }
        }

        /* Ignore signals */
        signal(SIGINT, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);

        while (1)
        {
            char path[PATH_MAX];

            /* Block here until parent sends a path */
            ssize_t rlen = read(dns_pipe_fd[0], &path, sizeof(path));
            if (rlen < 1)
            {
                if (rlen == -1 && errno == EINTR)
                {
                    continue;
                }
                close(dns_pipe_fd[0]);
                close(ack_pipe_fd[1]);
                exit(0);
            }

            path[sizeof(path) - 1] = '\0';
            int res = do_run_up_down_command(up, path, dns, tt);
            platform_unlink(path);

            /* Unblock parent process */
            while (1)
            {
                ssize_t wlen = write(ack_pipe_fd[1], &res, sizeof(res));
                if ((wlen == -1 && errno != EINTR) || wlen < (ssize_t)sizeof(res))
                {
                    /* Not much we can do about errors but exit */
                    close(dns_pipe_fd[0]);
                    close(ack_pipe_fd[1]);
                    exit(0);
                }
                else if (wlen == sizeof(res))
                {
                    break;
                }
            }

            up = !up; /* do the opposite next time */
        }
    }

    return true;
}

static void
run_up_down_command(bool up, const struct options *o, const struct dns_options *dns,
                    const struct tuntap *tt, struct dns_updown_runner_info *updown_runner)
{
    if (!dns->updown || (o->up_script && !dns_updown_user_set(dns) && !dns_updown_forced(dns)))
    {
        return;
    }

    int status = -1;

    if (!updown_runner->required)
    {
        /* Run dns updown directly */
        status = do_run_up_down_command(up, NULL, dns, tt);
    }
    else
    {
        if (updown_runner->pid < 1)
        {
            /* Need to set up privilege preserving child first */
            if (!run_updown_runner(up, dns, tt, updown_runner))
            {
                return;
            }
        }

        struct gc_arena gc = gc_new();
        const char *dvf = platform_create_temp_file(o->tmp_dir, "dvf", &gc);
        if (!dvf)
        {
            msg(M_ERR, "could not create dns vars file");
            goto out_free;
        }

        struct env_set *es = env_set_create(&gc);
        updown_env_set(up, dns, tt, es);
        env_set_write_file(dvf, es);

        int wfd = updown_runner->fds[1];
        ssize_t dvf_size = strlen(dvf) + 1;
        while (1)
        {
            ssize_t len = write(wfd, dvf, dvf_size);
            if (len < dvf_size)
            {
                if (len == -1 && errno == EINTR)
                {
                    continue;
                }
                msg(M_WARN | M_ERRNO, "could not send dns vars filename");
            }
            break;
        }

        int rfd = updown_runner->fds[0];
        while (1)
        {
            ssize_t len = read(rfd, &status, sizeof(status));
            if (len < (ssize_t)sizeof(status))
            {
                if (len == -1 && errno == EINTR)
                {
                    continue;
                }
                msg(M_WARN | M_ERRNO, "could not receive dns updown status");
            }
            break;
        }

out_free:
        gc_free(&gc);
    }

    msg(M_INFO, "dns %s command exited with status %d", up ? "up" : "down", status);
}

#endif /* _WIN32 */

void
show_dns_options(const struct dns_options *o)
{
    struct gc_arena gc = gc_new();

    int i = 1;
    struct dns_server *server = o->servers_prepull ? o->servers_prepull : o->servers;
    while (server)
    {
        msg(D_SHOW_PARMS, "  DNS server #%d:", i++);

        for (size_t j = 0; j < server->addr_count; ++j)
        {
            const char *addr;
            const char *fmt_port;
            if (server->addr[j].family == AF_INET)
            {
                addr = print_in_addr_t(server->addr[j].in.a4.s_addr, IA_NET_ORDER, &gc);
                fmt_port = "    address = %s:%s";
            }
            else
            {
                addr = print_in6_addr(server->addr[j].in.a6, 0, &gc);
                fmt_port = "    address = [%s]:%s";
            }

            if (server->addr[j].port)
            {
                const char *port = print_in_port_t(server->addr[j].port, &gc);
                msg(D_SHOW_PARMS, fmt_port, addr, port);
            }
            else
            {
                msg(D_SHOW_PARMS, "    address = %s", addr);
            }
        }

        if (server->dnssec)
        {
            msg(D_SHOW_PARMS, "    dnssec = %s", dnssec_value(server->dnssec));
        }

        if (server->transport)
        {
            msg(D_SHOW_PARMS, "    transport = %s", transport_value(server->transport));
        }
        if (server->sni)
        {
            msg(D_SHOW_PARMS, "    sni = %s", server->sni);
        }

        struct dns_domain *domain = server->domains;
        if (domain)
        {
            msg(D_SHOW_PARMS, "    resolve domains:");
            while (domain)
            {
                msg(D_SHOW_PARMS, "      %s", domain->name);
                domain = domain->next;
            }
        }

        server = server->next;
    }

    struct dns_domain *search_domain = o->search_domains;
    if (search_domain)
    {
        msg(D_SHOW_PARMS, "  DNS search domains:");
        while (search_domain)
        {
            msg(D_SHOW_PARMS, "    %s", search_domain->name);
            search_domain = search_domain->next;
        }
    }

    gc_free(&gc);
}

static void
free_applied_dns_options(struct dns_updown_runner_info *duri)
{
    gc_free(&duri->applied.gc);
    CLEAR(duri->applied);
    duri->applied_valid = false;
}

void
run_dns_up_down(bool up, struct options *o, const struct tuntap *tt,
                struct dns_updown_runner_info *duri)
{
    /* Bring down what was actually brought up, not what the options say
     * now. They might have been changed by a PUSH_UPDATE since then. */
    const struct dns_options *dns = up ? &o->dns_options : &duri->applied;
    if (!up && !duri->applied_valid)
    {
        return;
    }

    if (!dns->servers)
    {
        if (!up)
        {
            free_applied_dns_options(duri);
        }
        return;
    }
#ifdef _WIN32
    /* Don't use iservice in DHCP mode */
    const struct tuntap_options *tto = &o->tuntap_options;
    if (tto->ip_win32_type == IPW32_SET_DHCP_MASQ || tto->ip_win32_type == IPW32_SET_ADAPTIVE)
    {
        return;
    }
#endif

    /* Warn about adding servers of unsupported AF */
    const struct dns_server *s = dns->servers;
    while (up && s)
    {
        size_t bad_count = 0;
        for (size_t i = 0; i < s->addr_count; ++i)
        {
            if ((s->addr[i].family == AF_INET6 && !tt->did_ifconfig_ipv6_setup)
                || (s->addr[i].family == AF_INET && !tt->did_ifconfig_setup))
            {
                ++bad_count;
            }
        }
        if (bad_count == s->addr_count)
        {
            msg(M_WARN,
                "DNS server %ld only has address(es) from a family "
                "the tunnel is not configured for - it will not be reachable",
                s->priority);
        }
        else if (bad_count)
        {
            msg(M_WARN,
                "DNS server %ld has address(es) from a family "
                "the tunnel is not configured for",
                s->priority);
        }
        s = s->next;
    }

    if (up)
    {
        /* Remember what is brought up, so that exactly this is undone later.
         * A previous copy can exist when the tunnel is kept with --persist-tun. */
        free_applied_dns_options(duri);
        struct gc_arena gc = gc_new();
        duri->applied = clone_dns_options(dns, &gc);
        duri->applied.gc = gc;
        duri->applied_valid = true;
        dns = &duri->applied;
    }

#ifdef _WIN32
    run_up_down_service(up, o, dns, tt);
#else
    run_up_down_command(up, o, dns, tt, duri);
#endif /* ifdef _WIN32 */

    if (!up)
    {
        free_applied_dns_options(duri);
    }
}
