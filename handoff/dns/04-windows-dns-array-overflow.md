# 04: Windows/Android `--dns` → tuntap copy stores the 4th IPv4 address as IPv6 and fills arrays one short

- **Severity:** Medium
- **Platforms:** Windows (DHCP mode: tap-windows6 with `ip-win32 dynamic/adaptive`) and
  Android
- **Upstream:** no issue or PR found

## Where

`src/openvpn/options.c`: `tuntap_options_postprocess_dns()`, around lines 2775 and 2811-2817
(current branch: 2867, 2903-2909).

```c
while (d && tt->domain_search_list_len + 1 < N_SEARCH_LIST_LEN)    /* 9 of 10 */
...
if (s->addr[i].family == AF_INET && tt->dns_len + 1 < N_DHCP_ADDR) /* 3 of 4 */
{
    tt->dns[tt->dns_len++] = ntohl(s->addr[i].in.a4.s_addr);
}
else if (tt->dns6_len + 1 < N_DHCP_ADDR)                           /* <-- also taken for full AF_INET */
{
    tt->dns6[tt->dns6_len++] = s->addr[i].in.a6;
}
```

## What goes wrong

1. **IPv4 stored as IPv6.** Once the IPv4 array is full, the next IPv4 address goes to the
   `else if` branch. Its union is read as `in6_addr`, so `1.2.3.4` becomes the IPv6 DNS server
   `102:304::`.
   - **Android:** that address is sent as a `DNS6SERVER`.
   - **Windows DHCP:** it ends up in the DHCP options or the netsh IPv6 DNS list.
2. **Off-by-one limits.** The `+ 1 <` checks limit `--dns` to 3 IPv4 servers, 3 IPv6 servers
   and 9 search domains. `--dhcp-option` allows 4, 4 and 10 (`N_DHCP_ADDR`,
   `N_SEARCH_LIST_LEN`).
3. **Overflow warning never fires for IPv4.** The "couldn't copy all" warning is only set when
   *both* checks fail, so it never appears for a pure-IPv4 overflow.

## Reproduction

Android, or Windows with tap-windows6 in DHCP mode:

```
dns server 0 address 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4
```

- **Android:** the management log shows `DNS6SERVER a00:4::` (the 4th address).
- **Windows:** `--verb 4` shows the DHCP option dump.

## Proposed fix

```c
while (d && tt->domain_search_list_len < N_SEARCH_LIST_LEN) { ... }
...
for (size_t i = 0; i < s->addr_count; ++i)
{
    if (s->addr[i].family == AF_INET)
    {
        if (tt->dns_len < N_DHCP_ADDR)
            tt->dns[tt->dns_len++] = ntohl(s->addr[i].in.a4.s_addr);
        else
            overflow = true;
    }
    else
    {
        if (tt->dns6_len < N_DHCP_ADDR)
            tt->dns6[tt->dns6_len++] = s->addr[i].in.a6;
        else
            overflow = true;
    }
}
```

Check that `tt->domain_search_list` is used with an explicit length everywhere.
`do_dns_domain_service()` (tun.c) instead loops until it reaches a NULL entry, so filling all
10 slots must not read past the end. It is bounded by `i < N_SEARCH_LIST_LEN`, so it is fine.

## Tests

Unit-test `tuntap_options_postprocess_dns()`. It is built for `_WIN32 || TARGET_ANDROID`, so
add a test build with `TARGET_ANDROID` defined, or move the copy logic into a helper that can
be built on any platform. Cases:

- 4 and 5 IPv4 addresses
- mixed IPv4/IPv6
- 10 and 11 search domains
