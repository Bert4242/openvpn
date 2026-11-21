# 09: Small bugs in the shipped dns-updown scripts

- **Severity:** Low
- **Files:** `distro/dns-scripts/*.sh`
- **Upstream:** no issue or PR found. #1135 (OpenBSD script) touches the same directory.

## 9a: systemd: search domains out of order when there are 10 or more

`systemd-dns-updown.sh` ~69 and ~188: `for domain_var in ${!dns_search_domain_*}` expands the
names in sorted text order: `_1, _10, _11, _2, …`. The search order matters.

**Fix:** loop numerically:

```bash
local i=1
while :; do
    local v=dns_search_domain_$i
    [ -n "${!v}" ] || break
    list+="${!v} "
    i=$((i+1))
done
```

Note that this numeric loop also stops at the first gap. Fix 03 first, so that `_1` always
exists.

## 9b: openresolv: writes 2 nameservers and 5 search domains instead of 3 and 6

`openresolv-dns-updown.sh` ~70-86: `maxns=3` and `maxdom=6` are decremented *before* the
`-gt 0` check, so the loops end one entry early.

**Fix:** decrement after printing, or check `[ $i -le $maxns ]`. Also check the `maxns`
logic in the systemd script's resolv.conf fallback (~193).

## 9c (needs checking): openresolv gets one `search` line per domain

The openresolv script prints `search <domain>` once per domain. Plain resolv.conf keeps only
the *last* `search` line, but openresolv may merge them. Check with `resolvconf -l` and
`/etc/resolv.conf` after up. If only one domain survives, print a single
`search d1 d2 …` line.

## Tests

Shell tests: source each script with a small vars file and a stubbed
`resolvectl`/`resolvconf`, then compare the commands it issues.
