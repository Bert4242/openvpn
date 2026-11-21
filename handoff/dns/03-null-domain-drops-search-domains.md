# 03: `--dhcp-option DOMAIN-SEARCH` without `DOMAIN` loses all search domains in dns-updown

- **Severity:** Medium
- **Platforms:** Unix
- **Upstream:** no issue or PR found

## Where

`src/openvpn/options.c`: `dhcp_options_postprocess_dns()`, around lines 2903-2915 (current
branch: ~2995-3007).

```c
if (dhcp->dns_len || dhcp->dns6_len)
{
    struct dns_domain **entry = &dns->search_domains;
    ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, &dns->gc);
    struct dns_domain *domain = *entry;
    domain->name = dhcp->domain;          /* <-- may be NULL */
    entry = &domain->next;
    for (i...) { ... search_domain->name = dhcp->domain_search_list[i]; }
```

## What goes wrong

When there are no `--dns server` options, the `--dhcp-option` DNS values are converted into
`--dns` options for `dns-updown`. The first search-domain entry is always created, even when
`DOMAIN` was not given, so its name is `NULL`.

- **In `setenv_dns_options()`:** `setenv_str(es, "dns_search_domain_1", NULL)` *deletes* the
  variable. The script gets `dns_search_domain_2…N` but no `_1`.
- **Shipped scripts that stop at a missing `_1`, dropping every search domain:**
  - `openresolv-dns-updown.sh` (loop from i=1, `[ "${option}" ] || break`)
  - `macos-dns-updown.sh` (`search_domains_string`)
  - `resolvconf_file-dns-updown.sh` and `haikuos_file-dns-updown.sh` (`test -z
    "$dns_search_domain_1" || …`)
  - `systemd-dns-updown.sh`, in its resolv.conf fallback branch (~line 228)
- **Only unaffected path:** the systemd-resolved branch, which uses
  `${!dns_search_domain_*}`.
- **Other side effects:**
  - `show_dns_options()` passes NULL to `%s` (prints `(null)` on glibc; undefined behaviour
    elsewhere).
  - A custom `--dns-updown` sees numbering that starts at 2.

This is a common server setup: `push "dhcp-option DNS 10.8.0.1"` plus
`push "dhcp-option DOMAIN-SEARCH corp.example"`, with no `DOMAIN`.

## Reproduction

1. Client config on Linux with openresolv: `dhcp-option DNS 10.8.0.1` and
   `dhcp-option DOMAIN-SEARCH corp.example`.
2. Use `--dns-updown` pointing to a script that runs `env | grep dns_`.
3. **Expected:** `dns_search_domain_1=corp.example`.
4. **Actual:** only `dns_search_domain_2=corp.example`, and `resolvconf -l` shows no `search`
   line.

## Proposed fix

```c
struct dns_domain **entry = &dns->search_domains;
if (dhcp->domain)
{
    ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, &dns->gc);
    (*entry)->name = dhcp->domain;
    entry = &(*entry)->next;
}
for (unsigned int i = 0; i < dhcp->domain_search_list_len; ++i) { ... }
```

Optional: skip a `DOMAIN-SEARCH` entry that repeats `DOMAIN`.

## Tests

Unit-test `dhcp_options_postprocess_dns()`. It is `static`, so either expose it for tests or
test it through `options_postprocess_pull()`. Cases:

- DNS + DOMAIN-SEARCH without DOMAIN → the list starts with the first search domain and has
  no NULL names
- DNS + DOMAIN + DOMAIN-SEARCH → keeps the current order
