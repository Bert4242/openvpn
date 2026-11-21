# 08: Privileged dns-updown runner sources a file written by the unprivileged process, and unlinks any path it is sent

- **Severity:** Hardening (defence in depth). This only matters after the unprivileged
  OpenVPN process has already been compromised.
- **Platforms:** Unix with `--user`/`--group`, when the privileged runner is used.
- **Upstream:** no issue or PR found. Because this is security-related, consider reporting it
  privately (security@openvpn.net) rather than in a public issue.

## Where

`src/openvpn/dns.c`:

- `run_updown_runner()` (~624):
  - forks a child that keeps root privileges
  - reads a path from a pipe
  - runs `do_run_up_down_command(up, path, …)`, then `platform_unlink(path)` (~697)
- `run_up_down_command()` (~729-766): the unprivileged parent writes `name=value` lines with
  `env_set_write_file()` and sends the path.

`env_set_write_file()` (`env_set.c`) writes the lines with no quoting. Every shipped script
then *sources* the file as root:

```sh
[ -z "${dns_vars_file}" ] || . "${dns_vars_file}"
```

## What goes wrong

1. **Root command execution.** Whoever controls the unprivileged process controls the file
   contents. Sourcing them as root turns "compromised unprivileged OpenVPN" into root. The
   point of `--user` is to prevent exactly that.
   - Today, values *pushed by the server* can't inject shell code: `validate_domain()`
     restricts names to `[A-Za-z0-9._-]` and bytes ≥ 0x80, addresses must be numeric
     (`AI_NUMERICHOST`), and the other values come from fixed enums.
   - That safety is fragile: any future free-text `dns_*` variable becomes a shell-injection
     path.
2. **Arbitrary file deletion as root.** The runner unlinks *any* path it receives, so a
   compromised parent can delete any file.
3. **Unhandled partial pipe reads.** One `read()` of up to `PATH_MAX` is assumed to return
   the whole path.

## Proposed fix

- **Runner:**
  - Accept only paths in the expected form: inside `o->tmp_dir` (resolved once before
    privileges are dropped), with the `openvpn_dvf_` prefix, no `/../`, and a regular file
    owned by the unprivileged uid. Refuse anything else.
  - Better: send the variables themselves over the pipe (length-prefixed, at most N bytes) and
    have the root runner set them in its own `env_set`. Then no file is needed and nothing is
    unlinked.
- **Scripts:** if a file must stay, parse it instead of sourcing it. Read it line by line,
  accept only `^dns_[a-z0-9_]+=` and `^(dev|script_type)=` names, and validate the value
  characters.
- **Writer:** quote values in `env_set_write_file()`, e.g. `name='value'` with `'` escaped.
  This only protects against future values containing shell characters; it does not help
  against a compromised writer.

## Tests

- Unit-test the runner's path check, if it is split into a helper.
- Shell test: feed the scripts a vars file containing `dns_search_domain_1=$(touch /tmp/x)`
  and check that nothing is executed.
