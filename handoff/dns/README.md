# DNS handling: handoff notes

These notes come from a review of the client-side DNS code (`--dns`, `--dhcp-option`,
`--dns-updown`, the Windows interactive service, Android) and the related server-side code.

- **Code references:** upstream `OpenVPN/openvpn` master at `3b508e1`. All findings are still
  present there. Line numbers on branch `ccr-3a553326-ir0004` differ slightly, so search by
  function name.
- **Checked against:** upstream GitHub issues and PRs on 2026-11-21. Gerrit and the
  openvpn-devel mailing list were not searched.

| File | Severity | Area | Upstream tracking |
|---|---|---|---|
| [01-push-update-dns-wipes-updown.md](01-push-update-dns-wipes-updown.md) | High | client, PUSH_UPDATE | PR #1122 (closed, not merged) |
| [02-delete-all-dhcp-fo-unlink.md](02-delete-all-dhcp-fo-unlink.md) | High | client (Unix), PUSH_UPDATE | PR #1121 (closed, not merged) |
| [03-null-domain-drops-search-domains.md](03-null-domain-drops-search-domains.md) | Medium | client (Unix), dns-updown | none |
| [04-windows-dns-array-overflow.md](04-windows-dns-array-overflow.md) | Medium | client (Windows/Android) | none |
| [05-adapter-domain-suffix-spelling.md](05-adapter-domain-suffix-spelling.md) | Low | client (Unix) | none |
| [06-android-search-domains.md](06-android-search-domains.md) | Medium | client (Android) | none |
| [07-server-dns-capability-and-docs.md](07-server-dns-capability-and-docs.md) | Low/Medium | server, docs | related: #937, #1062 |
| [08-dns-vars-file-privsep-hardening.md](08-dns-vars-file-privsep-hardening.md) | Hardening | client (Unix), privilege separation | none |
| [09-dns-updown-script-nits.md](09-dns-updown-script-nits.md) | Low | distro/dns-scripts | none |
| [10-dns-option-parsing-nits.md](10-dns-option-parsing-nits.md) | Low | option parsing | none |
| [11-windows-domain-handling-gaps.md](11-windows-domain-handling-gaps.md) | Low/Medium | client (Windows) | related: #326, #1117 |
| [12-up-script-foreign-option-mapping.md](12-up-script-foreign-option-mapping.md) | Low | client (Unix), compatibility | none |

## Verification status

- **02:** confirmed by running a test program built from the function's own source.
- **All others:** found by reading the code. OpenVPN was not built and no client/server run
  was done.

Each note gives a reproduction to confirm the issue before fixing it.
