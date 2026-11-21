# 10: Small issues in `--dns` option parsing

- **Severity:** Low
- **Files:** `src/openvpn/dns.c`, `src/openvpn/options.c` (`check_dns_option`)
- **Upstream:** no issue or PR found

## 10a: empty priority accepted as 0

`dns_server_priority_parse()` (`dns.c` ~184) does not check `endptr == str`, so `dns server ""
address …` is accepted as server 0.

**Fix:**

```c
if (endptr == str || *endptr != '\0' || ...) return false;
```

Optionally also check `errno`.

## 10b: `[::1]` without a port is rejected

In `dns_server_addr_parse()` (`dns.c` ~67), a bracketed IPv6 address must have a port. The man
page says brackets are needed only *when* a port is given, but users naturally write `[::1]`.

**Fix:** if `addr[0] == '['` and the string ends with `]`, remove the brackets and parse it
with no port.

## 10c: invalid address leaves the earlier addresses added

In `check_dns_option()`, `dns server n address a b BAD` adds `a` and `b` to the server and then
returns false. For pushed options the error is not fatal, so the server keeps a partial
address list.

**Fix:** parse into a temporary `struct dns_server` and copy it over only when every address
parses.

## 10d (optional): `sni` accepted without DoT/DoH transport

`dns_options_verify()` checks only `addr_count`. An `sni` without `transport DoT|DoH` is
silently meaningless. Log a warning.

## Tests

Extend `tests/unit_tests/openvpn/test_options_parse.c` or add `test_dns.c` with these cases:

- `""`, `"-0"` and `"128"` as priorities
- `"[::1]"`, `"[::1]:53"`, `"[::1]:"` and `"::1:53"` as addresses
- a partially invalid address list (expect no change to the server)
