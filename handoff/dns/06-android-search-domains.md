# 06: Android never receives search domains (`--dns search-domains` / `DOMAIN-SEARCH`)

- **Severity:** Medium
- **Platforms:** Android (also affects other apps that use the management-interface "android"
  control protocol)
- **Upstream:** no issue or PR found

## Where

- `src/openvpn/tun.c`, around line 2029, in the Android `open_tun`:
  ```c
  if (tt->options.domain)
      management_android_control(management, "DNSDOMAIN", tt->options.domain);
  ```
  `tt->options.domain_search_list` is never sent.
- `src/openvpn/options.c`: `tuntap_options_postprocess_dns()`. With `--dns servers` present,
  `--dns search-domains` are copied into `tt->domain_search_list`, but `tt->domain` is never
  set from `--dns`.

## What goes wrong

| Config | What Android receives |
|---|---|
| `--dns` | no domain at all |
| `--dhcp-option` | only `DOMAIN`; `DOMAIN-SEARCH` is silently ignored |
| `--dns server n resolve-domains` (split DNS) | ignored (not supported by design) |

The man page says "On Android DNS will be passed via management interface", which suggests the
domains are passed too.

## Proposed fix

This needs agreement with the Android app (ics-openvpn), because the control protocol changes.

1. **Add a new control command,** e.g. `DNSSEARCHDOMAIN <domain>`, sent once per entry of
   `tt->options.domain_search_list`. Old apps answer unknown commands with an error or ignore
   them; check how `management_android_control` handles that.
2. **Optional fallback:** when there is no `tt->domain` but there are search domains, send the
   first search domain as `DNSDOMAIN`.
3. **Optional, later:** pass resolve-domains so the app can configure per-domain DNS.

## Tests

Use a management-interface mock and check that an Android build with `--dns search-domains a
b` produces the expected `DNSDOMAIN` and `DNSSEARCHDOMAIN` lines.
