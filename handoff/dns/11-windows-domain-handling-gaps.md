# 11: Windows: inconsistent DNS suffix and search-domain handling

- **Severity:** Low/Medium
- **Platforms:** Windows
- **Upstream:** related open issues on the same subject (these gaps may explain parts of
  them):
  - #326: no DNS suffix with DCO through openvpn-gui
  - #1117: `dhcp-option DOMAIN` suffix regression since 2.6.15
  - #1047: stale NRPT rules

## 11a: without the interactive service, `DOMAIN-SEARCH` is ignored

`tun.c` `do_dns_domain_pwsh()` (~411) sets only `tt->options.domain` as the
`ConnectionSpecificSuffix`. `domain_search_list` is never applied, and no warning is logged.

**Fix:** log a warning when `domain_search_list_len > 0` and the service is not used.
Alternatively, set the list with PowerShell
`Set-DnsClientGlobalSetting -SuffixSearchList`. Be careful: that setting is global, needs
admin rights and needs undo handling.

## 11b: with the interactive service, `DOMAIN` is dropped when a search list exists

`tun.c` `do_dns_domain_service()` (~199):

```c
/* only use domain when there are no search domains */
if (o->domain && !o->domain_search_list[0])
```

When both are pushed, the adapter suffix (`DOMAIN`) is silently dropped.

**Fix:** decide what the intended behaviour is and document it in #937. Possibly add
`DOMAIN` as the first search entry, unless it is already in the list.

## 11c: DHCP mode keeps old search domains after an update without any

`options.c` `tuntap_options_postprocess_dns()` resets `tt->domain_search_list_len` only
`if (d)`, that is, only when new `--dns search-domains` exist. Earlier entries are never
cleared. `dhcp.c` (~368) builds the DHCP offer from `domain_search_list_len`, so after a
PUSH_UPDATE that drops `search-domains`, the old ones can still be offered.

**Fix:** always reset `domain_search_list_len = 0` and `CLEAR(tt->domain_search_list)` on the
`--dns` path.

## 11d: NRPT applies only the first compatible server, and DNSSEC `optional` is dropped

- `dns.c` `run_up_down_service()` (~420) sends only the first `--dns` server that is plain and
  on port 53.
- `dnssec optional` is not sent; only `yes` sets `nrpt_dnssec`.

Both look intended (the docs say "Only the group of options corresponding to the lowest server
id is applied"). They should still be logged at `D_LOW` so users understand why a DoT server
was skipped.

## Tests

Windows-only. Use manual checks with `Get-DnsClient`, `Get-DnsClientNrptPolicy` and
`Get-DnsClientGlobalSetting` for each case, plus a unit test for 11c if 04's helper refactor
is done.
