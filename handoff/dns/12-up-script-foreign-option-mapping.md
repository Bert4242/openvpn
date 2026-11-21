# 12: `--dns search-domains` exported to `--up` scripts as several `dhcp-option DOMAIN` entries

- **Severity:** Low (compatibility)
- **Platforms:** Unix, `--up` script without a user-defined or forced `--dns-updown`
- **Upstream:** no issue or PR found

## Where

`src/openvpn/options.c` `dhcp_options_postprocess_dns()` ~2939:

```c
while (d)
{
    setenv_foreign_option(o, "DOMAIN", d->name, es);
    d = d->next;
}
```

## What goes wrong

For compatibility, `--dns` options are turned into `foreign_option_N` variables for old
`--up` scripts (`update-resolv-conf`, `update-systemd-resolved`, NetworkManager plugins).
Those scripts expect at most one `DOMAIN` (the connection suffix) and use `DOMAIN-SEARCH` for
the search list. With several `DOMAIN` entries, most of them keep only the last (or the
first) value, so the remaining search domains are lost.

## Proposed fix

Export the first search domain as `DOMAIN` and the rest as `DOMAIN-SEARCH`:

```c
bool first = true;
for (d = dns->search_domains; d; d = d->next)
{
    setenv_foreign_option(o, first ? "DOMAIN" : "DOMAIN-SEARCH", d->name, es);
    first = false;
}
```

Or export all of them as `DOMAIN-SEARCH` and only the first as `DOMAIN`. Check what common
scripts expect before choosing, and document the mapping in
`doc/man-sections/script-options.rst` (the `--dns-updown` section).

**Separate gap:** `resolve-domains` (split DNS) has no `dhcp-option` equivalent, so it is
dropped silently. Log this at `D_LOW`.

## Tests

1. Config: `--up` set to a dummy script, plus `dns server 0 address 10.0.0.1` and
   `dns search-domains a b c`.
2. Assert that `foreign_option_*` holds `DOMAIN a`, `DOMAIN-SEARCH b`, `DOMAIN-SEARCH c` and
   `DNS 10.0.0.1`.
