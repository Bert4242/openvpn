# 05: `ADAPTER_DOMAIN_SUFFIX` vs `ADAPTER-DOMAIN-SUFFIX` mismatch

- **Severity:** Low
- **Platforms:** Unix
- **Upstream:** no issue or PR found

## Where

- **Parser** (`options.c` ~6418) accepts the underscore form, which is also what
  `doc/man-sections/vpn-network-options.rst:161` documents:
  `streq(p[1], "DOMAIN") || streq(p[1], "ADAPTER_DOMAIN_SUFFIX")`
- **Environment cleanup** in `dhcp_options_postprocess_dns()` (`options.c` ~2882) matches the
  dash form instead: `strncmp(item_val + 12, "ADAPTER-DOMAIN-SUFFIX ", 22)`

## What goes wrong

When `--dns server` options are present, or `--dns-updown` is user-defined or `force`d, the
DNS-related `foreign_option_*` entries should be removed, because `--dns` overrides
`--dhcp-option`. `dhcp-option ADAPTER_DOMAIN_SUFFIX x` never matches the dash form, so it
stays in the environment and `--up` scripts still see it.

## Fix

Match the spelling the parser accepts:

```c
&& strncmp(item_val + 12, "ADAPTER_DOMAIN_SUFFIX ", 22) != 0
```

The parser does not accept the dash form, so only the underscore form needs to match. Better
still, make the cleanup and the parser share one list of DNS-related dhcp-option names, so
they cannot drift apart again.

## Tests

1. Config: `dns server 0 address 10.0.0.1` and `dhcp-option ADAPTER_DOMAIN_SUFFIX corp`.
2. After postprocessing, assert that no `foreign_option_*` holds `ADAPTER_DOMAIN_SUFFIX`.
