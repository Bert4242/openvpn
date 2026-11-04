# TODO: switch multi-listener-2 from `<listener>` to `<local>` blocks

Status: not started (phase 2 of the plan, kept for a second session).
Prerequisite: branch `multi-listener-upstream` (phase 1) exists and is tested.

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

## What to do

1. Tag the current tip so the `<listener>` version stays reachable, and push the
   tag: `git tag multi-listener-2-listener-syntax origin/multi-listener-2`.
2. Rebuild `multi-listener-2` from `origin/sni-gateway-modes-6`:
   1. cherry-pick the `multi-listener-upstream` commits (the SNI-free `<local>`
      block);
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
      - remove `--listener` / `<listener>`, `parse_listener_spec()`,
        `parse_listener_block_body()` and the `<tag arg>` change in
        `options_parse.c`.
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
     accepting only its own path;
   - a UDP socket on the same port number;
   - inheritance from a global `sni-gateway-server auto`;
   - the 18-case expired-cert suite (`scratch/suite.sh` in the
     ignore-cert-expiry worktree) on the rebuilt my-master;
   - `dev-tools/build-deb.sh` on the result.
6. Update `dev-tools/README.my-master.md` (the multi-listener-2 row of the
   table) and the memory notes. Tell the user that configs using
   `<listener SPEC>` must be rewritten as a `<local>` block with a `local` line
   inside.

## Notes from phase 1

(Filled in while building `multi-listener-upstream`.)
