# 01: PUSH_UPDATE `dns` / `-dns` wipes `--dns-updown` and the local DNS settings

- **Severity:** High
- **Platforms:** all. The visible failure is on Unix; Windows is affected only in the `-dns`
  case.
- **Upstream:** PR #1122 described this exact problem. It was closed without merging on
  2026-10-13. Commit `7c1328a` (2026-11-10) moved the faulty code into a shared helper but did
  not fix it.

## Where

- `src/openvpn/options.c`:
  - `reset_dns_options()`, around line 3612
  - its callers: `remove_option()` (`-dns`, ~3707) and `update_option()` (first `dns` line
    of an update, ~3962)
  - on the current branch the code is inline: `options.c:3729` and `:4047`
- `src/openvpn/dns.c`: `run_dns_up_down()` returns early when there are no servers (~895).

```c
static void
reset_dns_options(struct options *options)
{
    gc_free(&options->dns_options.gc);
    CLEAR(options->dns_options);
}
```

## What goes wrong

`CLEAR` zeroes all of `struct dns_options`. Only the pushed servers and search domains should
be reset, but it also clears:

- `updown` and `updown_flags`: the `--dns-updown` command, or the default command, and the
  `force` flag
- the local `--dns server` entries (already merged into `servers` after the first pull) and
  the local `search-domains`
- `from_dhcp`: the DNS values from `--dhcp-option`, both from the config and pushed

What follows in `incoming_push_message()`, then `options_postprocess_pull()`, then
`do_update()`:

1. **Old DNS is not removed (Unix).** `do_close_tun()` calls `run_dns_up_down(false, …)`, but
   `run_up_down_command()` returns because `dns->updown == NULL`. The old resolver settings
   stay in place (resolv.conf, openresolv, macOS scutil).
2. **New DNS is not applied (Unix).** `do_open_tun()` calls `run_dns_up_down(true, …)`, which
   returns for the same reason.
3. **Local overrides are lost.** `dns_options_postprocess_pull()` merges with
   `servers_prepull == NULL`, so `--dns server -1 …` overrides are dropped for the rest of the
   session.
4. **Stale NRPT rule with `-dns` and no replacement (Windows).** The server list is empty, so
   `run_dns_up_down()` returns at its first check. The service never gets
   `msg_del_nrpt_cfg`, and the old NRPT rule stays until the process exits. Possibly related
   to #1047.
5. **Spurious validation failure.** In `update_option()`, `check_dns_option()` runs *before*
   the reset and appends to the existing list. If the server with that priority already has
   addresses, valid updates fail: for example 5 existing + 4 new > 8 gives "malformed address
   or maximum exceeded".
6. **Down step uses the new settings.** `run_dns_up_down(false)` runs with the *new* options,
   because the options are changed before `do_update()` closes the tun. A custom
   `--dns-updown` script gets the new values in its `dns-down` call.

## Reproduction

1. **Server:** 2.7 with PUSH_UPDATE support. Push `dns server 0 address 10.8.0.1` and
   `dns search-domains a.example`.
2. **Client (Linux):** use `--dns-updown` pointing to a script that logs `$script_type` and
   the `dns_*` variables. Optionally add `--dns server -1 address 192.0.2.53` as a local
   override.
3. **Trigger the update** from the server management interface:
   `push-update-cid <cid> "dns server 0 address 10.8.0.2"`.
4. **Expected:** a `dns-down` run for the old settings, then a `dns-up` run with 10.8.0.2 and
   the local server -1 still present.
5. **Actual:** neither script call happens. The log has no "dns up/down command exited"
   lines after the update.

## Proposed fix

Reset only the parts that come from the push, starting from the state saved before the pull.
`pre_connect_save()` runs after `dns_options_preprocess_pull()`. Its
`o->pre_connect->dns_options` therefore holds the local servers in `servers_prepull`, the
local search domains, and `updown`/`updown_flags`.

Sketch:

```c
static void
reset_dns_options(struct options *options)
{
    struct dns_options *dns = &options->dns_options;
    const struct dhcp_options from_dhcp = dns->from_dhcp; /* dhcp-option is reset separately */
    const char *updown = dns->updown;
    const enum dns_updown_flags updown_flags = dns->updown_flags;
    struct gc_arena old_gc = dns->gc;  /* save before *dns is overwritten */
    struct gc_arena gc = gc_new();

    if (options->pre_connect)
    {
        /* local servers come back in servers_prepull, local search domains in search_domains */
        *dns = clone_dns_options(&options->pre_connect->dns_options, &gc);
        /* the merge in dns_options_postprocess_pull() expects pulled servers in ->servers */
        dns->servers = NULL;
    }
    else
    {
        CLEAR(*dns);
    }
    dns->updown = updown;
    dns->updown_flags = updown_flags;
    dns->from_dhcp = from_dhcp;
    dns->gc = gc;
    gc_free(&old_gc);
}
```

Notes for whoever implements this:

- **gc lifetime.** `from_dhcp` holds `const char *` values from the push buffer's gc
  (`options->gc`), not from `dns_options.gc`, so copying it is safe. Free the old arena
  *after* cloning; the clone comes from `pre_connect` (`options->gc`), not from the old
  arena. See #1061 (GC cleanup) for related concerns.
- **Validation in `update_option()`.** Do the reset first and then call
  `add_option()`/`check_dns_option()` once. Alternatively, validate against a scratch
  `struct dns_options`. Either way, validation should not depend on the old list.
- **Windows `-dns` with no replacement.** Make sure the down step still runs. One option: in
  `do_update()`, run `run_dns_up_down(false, …)` with the *old* options before applying the
  push. Another: track "DNS currently applied" in `c->persist` instead of checking
  `o->dns_options.servers` on the down call.

## Tests

- **Unit test** (`tests/unit_tests/openvpn/test_options_parse.c` or a new
  `test_dns_options.c`): build options with `updown`, `updown_flags = DNS_UPDOWN_FORCED`, a
  local server with priority -1, and a pushed server 0. Then:
  - Call `update_option()` with a `dns server 0 address …` line. Assert that `updown` and its
    flags are kept, and that after `options_postprocess_pull()` the list holds -1 and the new
    0.
  - Same with `-dns` via `remove_option()`.
  - A server that already has 5 addresses, updated with 4 new ones: must succeed.
- **Note:** `test_push_update_msg.c` mocks `update_option()`, so it cannot catch this bug.
