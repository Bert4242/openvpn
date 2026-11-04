# TODO: switch multi-listener-2 from `<listener>` to `<local>` blocks

Status: not started (phase 2 of the plan, kept for a second session).
Prerequisite: done. Branch `multi-listener-upstream` (phase 1) is two commits,
pushed, based on upstream/master f1721dc7 (worktree
`../openvpn-sni-wt-multi-listener-upstream`):
- 90a5d3a3 Add `<local>` blocks: per-socket options for listening sockets;
- f591598d Accept `<listener>` as another name for a `<local>` block (added
  2026-11-04 at the user's request, a separate commit so it can be dropped if
  upstream objects).

## Why

`multi-listener-2` (the branch merged into `my-master`) declares per-socket
settings with a `<listener SPEC>` block. For the version meant for upstream
OpenVPN (`multi-listener-upstream`), the user chose a `<local>` block modelled
on `<connection>` instead:

```
<local>
local 0.0.0.0 443 tcp
sndbuf 393216
sni-gateway-server sni-http-path-upgrade      # only in multi-listener-2
sni-gateway-server-http-path /alpha
</local>
local 0.0.0.0 1194 udp
```

`<listener>` had three problems that a rename alone would not fix:
- its opening line takes an argument (`<listener tcp4:0.0.0.0:443>`), which
  needed a change in the config file reader (`check_inline_file()` in
  `options_parse.c`);
- it uses a second address format (`proto:host:port`);
- its body goes through a hand-written mini-parser
  (`parse_listener_block_body()`), not the normal option handlers.

`<local>` has none of these. The user decided (2026-11-04) that their own branch
should use the same syntax as the upstream one, so their configs keep working
whatever upstream decides.

The user then asked for `<listener>` as another name for the block: it marks a
server's listening socket, apart from a client's `--local`, in case the two
ever need to differ. It is the same block, with the same `local` line inside:

```
<listener>
local 0.0.0.0 443 tcp
sni-gateway-server sni-http-path-upgrade
</listener>
```

So the name `<listener>` stays; what goes away is the argument in its opening
line, the `proto:host:port` format and the mini-parser.

## What to do

1. Tag the current tip so the `<listener>` version stays reachable, and push the
   tag: `git tag multi-listener-2-listener-syntax origin/multi-listener-2`.
2. Rebuild `multi-listener-2` from `origin/sni-gateway-modes-6`:
   1. cherry-pick both `multi-listener-upstream` commits (the SNI-free `<local>`
      block, and its `<listener>` name);
   2. add one commit, "allow the sni-gateway-server options in `<local>`":
      - add `OPT_P_LOCAL` to the `VERIFY_PERMISSION` of `sni-gateway-server`,
        `-host`, `-ignore-alpn`, `-http-path` and `-http-upgrade-token`;
      - add the SNI fields to `struct local_socket_opts`, with `_defined` flags,
        copied from the sub-options in the `<local>` handler;
      - reuse from the current multi-listener-2 (`git show multi-listener-2-listener-syntax`):
        - `options_postprocess_mutate_le()`: the global host/ALPN filters are
          inherited only by sni/auto sockets, path/token only by http/auto;
        - `sni_gw_server_verify()`, with errors prefixed `<local SPEC>: `;
        - socket.c: the phase-1 `SF_SNI_GW_SERVER_*` flags and the phase-2
          `stream_buf` fields, taken from `sock->local_entry->opts`;
      - man page: list the SNI options as allowed inside `<local>`;
      - remove the old `--listener` option, the `<listener SPEC>` form (with an
        argument), `parse_listener_spec()`, `parse_listener_block_body()` and the
        `<tag arg>` change in `options_parse.c`. The argument-free `<listener>`
        from the cherry-picked commit stays. Check that the `listener` handler
        of the old code is fully gone, so it cannot shadow the cherry-picked
        `(streq(p[0], "local") || streq(p[0], "listener")) && is_inline`
        branch.
3. Force-push `multi-listener-2` with lease. `TOPICS` in
   `dev-tools/rebuild-my-master.sh` stays `multi-listener-2:sni-gateway-modes-6`.
4. Run `dev-tools/rebuild-my-master.sh`. The recorded rerere resolution for
   `options.c` (ignore-cert-expiry vs multi-listener-2, in
   `options_postprocess_verify()`) may no longer match. If asked, resolve once:
   keep both, the per-socket SNI verify loop first, then the ignore-cert-expiry
   warning.
5. Re-run the earlier live tests, translated to `<local>` (harness:
   `../openvpn-sni-wt-multi-listener-2/scratch/cli.sh`, configs in its
   `scratch/logs/*.conf`; PKI in `../openvpn-sni-wt-ignore-cert-expiry/scratch/pki`):
   - two TCP sockets with different `sni-gateway-server-http-path`, each
     accepting only its own path (one written `<listener>`, one `<local>`);
   - a UDP socket on the same port number;
   - inheritance from a global `sni-gateway-server auto`;
   - the 18-case expired-cert suite (`scratch/suite.sh` in the
     ignore-cert-expiry worktree) on the rebuilt my-master;
   - `dev-tools/build-deb.sh` on the result.
6. Update `dev-tools/README.my-master.md` (the multi-listener-2 row of the
   table) and the memory notes. Tell the user how to rewrite configs using
   `<listener SPEC>`: keep `<listener>`, move the address into a `local` line
   inside, e.g. `<listener tcp4:0.0.0.0:443>` becomes `<listener>` followed by
   `local 0.0.0.0 443 tcp4`; the rest of the block is unchanged
   (`[::1]` bracket addresses become `local ::1 PORT tcp6`).

## Notes from phase 1 (2026-11-04)

- **Shape of the upstream commit (90a5d3a3), single commit:**
  - `options.h`: `struct local_socket_opts` (rcvbuf/sndbuf -1 = not set, mark 0,
    bind_dev NULL, mtu_discover_type -1, bind_ipv6_only ORed), and
    `local_entry.has_opts` + `.opts`; `OPT_P_LOCAL (1ull << 33)`.
  - `options.c`: `add_local_block()` (just above `add_option()`), dispatched by
    `streq(p[0], "local") && is_inline` **before** the plain `local` handler.
    `OPT_P_LOCAL` is on local, rcvbuf, sndbuf, mark, bind-dev, mtu-disc and bind.
    A server-only check sits next to "multiple --local statements only allowed".
  - `socket.c` phase1: `le`, the `tmp_sock->local_entry` child fix, `lo`, and the
    per-field ternaries; `socket.h`: `struct link_socket.local_entry`.
  - `options_show.c`: one extra `<local> ...` line per block entry.
- **For the SNI commit**, the SNI options follow the same pattern:
  - add `OPT_P_LOCAL` to their handlers;
  - copy `sub.sni_gw_server_*` in `add_local_block()`. The SNI lists
    (host/path) are arrays allocated in sub's gc, which `gc_transfer()` moves
    along; a "defined" flag is needed for `sni-gateway-server` itself
    (`sub.sni_gw_server_enabled`);
  - `options_postprocess_mutate_le()` exists upstream too (port/proto
    defaults); the SNI inheritance from multi-listener-2 goes in there.
- **`socket-flags`** is a no-op upstream now (only TCP_NODELAY, and it has no
  effect), so it is not a per-socket option. multi-listener-2's per-listener
  `sockflags` field goes away.
- **`<listener>` name (f591598d):** `add_local_block()` takes the tag as
  written, for the messages ("Each <listener> block ...", "[LISTENER-OPTIONS]");
  the server-only error names both. Live-tested like `<local>`: a server with
  one `<listener>`, one `<local>` and a plain UDP `local` (strace: per-socket
  options as before), the error cases (`scratch/logs/ha-*.conf`), a plain
  `listener` line is "Unrecognized option", nested in `<local>` and in
  `<connection>` rejected.
- **No unit test** can cover `add_local_block()`: no unit test links the real
  `options.c`. Tests are live: `scratch/srv.conf` (two TCP blocks + a UDP plain
  local) and the error configs `scratch/logs/e-*.conf` in the upstream
  worktree.
- **strace** (installed) is the way to see per-socket options:
  `sudo strace -f -e trace=accept,setsockopt,bind openvpn --config ...`. `ss`
  in this container does not show the fwmark. SO_MARK needs root.
- **Test pitfalls:**
  - several clients sharing `cli-valid.crt` need `duplicate-cn` on the
    server, or the server keeps dropping the older one;
  - kill test servers with `pkill -f '^/full/path/openvpn'`. A pattern that
    is also in your own bash command line kills the shell itself.
- **Formatting:** upstream now uses clang-format (`.clang-format`, ColumnLimit
  0). Run `git diff -U0 | clang-format-diff -p1 -i -binary clang-format`
  (installed).
- **Base drift:** `multi-listener-upstream` sits on upstream/master f1721dc7,
  which is newer than `sni-gateway-modes-6`'s base. Cherry-picking it onto
  sni-6 may conflict in context lines. Alternatively, run
  `rebuild-my-master.sh --sync --rebase-topics` first, so that sni-6 sits on
  current master.
