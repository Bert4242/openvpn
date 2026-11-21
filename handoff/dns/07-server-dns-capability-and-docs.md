# 07: Server pushes `dns` without checking the client's `IV_PROTO_DNS_OPTION_V2`; IV_PROTO docs out of date

- **Severity:** Low/Medium (compatibility and documentation)
- **Platforms:** server, docs
- **Upstream:** no direct issue. Related:
  - #937: improve the `--dns` docs
  - #1062: warn on `dns`/`dhcp-option` in a server config

## Where

- `src/openvpn/ssl.c` ~2032: the client sets `IV_PROTO_DNS_OPTION_V2` (bit 11) and no longer
  sends bit 6 (`ssl.h:99`: "Not sent anymore").
- The server code never checks bit 6 or bit 11; the push code contains no reference to them.
- `doc/man-sections/client-options.rst` ~398-415:
  - documents bit 6 as "The client is capable of parsing and receiving the `--dns` pushed
    option"
  - stops at bit 10
  - does not mention bit 11 (`DNS_OPTION_V2`) or bit 12 (`PUSH_UPDATE`)

## What goes wrong

- **Older clients receive lines they can't parse.** Operators who push `dns …` send them
  unchanged to:
  - pre-2.6 clients, which don't know `--dns`
  - early 2.6 clients, which use the incompatible v1 syntax
  These clients log option errors and get no DNS configuration.
- **No built-in fallback.** Operators must check `IV_PROTO` themselves in a
  `--client-connect` script and push `dhcp-option` instead. The docs describe bit 6 as the
  thing to test, but current clients don't send it.

## Proposed work

1. **Docs (simple):**
   - Mark bit 6 as historic.
   - Document bit 11 ("supports the `--dns` option in its 2.6.x-final / 2.7 form") and bit 12
     (PUSH_UPDATE).
   - Add a short example `client-connect` snippet that chooses `dns` or `dhcp-option` from
     `IV_PROTO`.
2. **Server feature (needs maintainer agreement):** when a client lacks bit 11, convert
   pushed `dns` options into an equivalent `dhcp-option DNS/DNS6/DOMAIN-SEARCH`. Convert only
   the lowest-priority server, and only when it is a plain server on port 53 without DNSSEC,
   using the same rules as `dhcp_options_postprocess_dns`. This must be optional, or at least
   logged, because the output changes.
3. **#1062:** warn when `--dns` or `--dhcp-option` appears in a `--server` config without
   `push`. Not a bug, but the same kind of confusion between server and client settings.

## Tests

- **Docs:** none needed.
- **Feature:** add a unit test for the push-buffer builder, run with a fake `peer_info` with
  and without bit 11.
