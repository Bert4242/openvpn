# my-master: HOWTO

`my-master` is this fork's own build branch: the official OpenVPN `master` plus
the local work that is not (yet) upstream.  It is never edited by hand; a
script rebuilds it from its parts.  A second script turns it into a `.deb`
for the servers.

## What is in it

| Branch                | What it adds                                        | Built on              |
|-----------------------|-----------------------------------------------------|-----------------------|
| `sni-gateway-modes-6` | `--sni-gateway-server` / `--sni-gateway-client`     | `master`              |
| `multi-listener-2`    | `<listener>` blocks: several ports, per-port settings | `sni-gateway-modes-6` |
| `ignore-cert-expiry`  | `--ignore-cert-expiry`, `--ignore-cert-expiry-fingerprint` | `master`       |
| `my-master-tools`     | these scripts and this file                         | `master`              |

The list lives in the `TOPICS` array at the top of
`dev-tools/rebuild-my-master.sh`.  To add or drop a branch, or to switch to
`sni-gateway-modes-7` one day, edit it there (on `my-master-tools`).

Each build is tagged `my-master-YYYY-MM-DD` (`.2`, `.3`, ... for more builds
the same day), so any earlier build can be found again:
`git tag -l 'my-master-*'`.

## Where to run things

Everything below runs in the `my-master` worktree:

```
cd ../openvpn-sni-wt-my-master
```

It must be clean (no uncommitted changes).  Don't commit on `my-master`: it
is thrown away and rebuilt each time.  Fix things on the branch they belong
to, push it, then rebuild.

## 1. Update everything after upstream OpenVPN moved

```
dev-tools/rebuild-my-master.sh --sync --rebase-topics
```

This:

1. fast-forwards this fork's `master` to the upstream OpenVPN `master`
   (`--sync`; it refuses if the fork's `master` has commits of its own);
2. moves each branch of the table onto its new base (`--rebase-topics`)
   and force-pushes it;
3. rebuilds `my-master` from `master` plus the branches, tags it, and
   force-pushes it.

To see what would happen first, add `--no-push`: everything is done
locally, nothing is pushed, and your local branches stay as they were.
Afterwards, `git reset --hard origin/my-master` and
`git tag -d my-master-<date>` undo the local result.

Lighter variants:

| Command                                   | Effect                                                   |
|-------------------------------------------|----------------------------------------------------------|
| `rebuild-my-master.sh`                    | rebuild `my-master` from the fork's `master` as it is; branches untouched |
| `rebuild-my-master.sh --sync`             | same, after updating the fork's `master` from upstream   |
| `rebuild-my-master.sh --rebase-topics`    | also move the branches onto the current `master`         |

Moving the branches (`--rebase-topics`) is optional: `my-master` gets the new
`master` either way.  It keeps the branches themselves current, which matters
when one is to be proposed upstream.

### When it stops on a conflict

Git remembers how each conflict was resolved (`rerere`) and replays it in
later runs, so a conflict needs fixing by hand only once.  When a new one
appears, the script stops and names the files:

- during a **merge** (rebuilding `my-master`): fix the files, `git add` them,
  `git commit`, then run the script again with the same options;
- during a **rebase** (moving a branch): fix the files, `git add` them,
  `git rebase --continue` until it is done, then run the script again with
  the same options.

Nothing is pushed until every step went through, so stopping halfway is safe.
The rerun starts over and replays the resolution you just made.

If a branch was moved while another worktree has it checked out, the script
says so; update that worktree with `git fetch && git reset --hard origin/<branch>`
(after checking it has no work of its own).

## 2. Build the .deb

```
dev-tools/build-deb.sh            # add --check to also run the unit tests
```

Result: `scratch/deb/openvpn_<version>_<arch>.deb`, built from the commit
that is checked out (so from the latest `my-master` after step 1).  The
first run says which build packages are missing and how to install them.

How it works: it compiles OpenVPN with the same options as Debian, then takes
Debian's own `openvpn` package and swaps in only the new program, plugins and
man pages.  Debian's services (`openvpn@NAME`, `openvpn-server@NAME`,
`openvpn-client@NAME`), `/etc/default/openvpn` and install scripts stay as
they are, so existing server setups keep working.

The version looks like `2.8~git202611012022.f672ed49+deb13`:

- it is higher than the distribution's 2.6.x, so `apt upgrade` won't swap it
  back;
- later builds get higher versions (commit date), so each new one installs as
  an upgrade;
- `/usr/share/doc/openvpn/README.local-build` on the server says what it was
  built from.

**One build per OS version.**  The package is linked against the libraries
of the machine that built it.  Build on Debian 13 for Debian 13 servers, on
Ubuntu 24.04 for Ubuntu 24.04, and so on (any machine or container of
that release works, as long as apt can download packages).

## 3. Install on a server

```
scp scratch/deb/openvpn_*.deb server:
ssh server
sudo apt install ./openvpn_*.deb
sudo systemctl restart openvpn@NAME        # or openvpn-server@NAME
journalctl -u openvpn@NAME -n 50           # check it came up
```

Installing does **not** restart running VPNs, so it is safe to do over the
VPN itself; the restart is the moment the connection drops.

The first time, try one server before the others: it moves from OpenVPN 2.6
to the development version 2.8, and some old options were removed after
2.6.  Read the log right after the restart.

Back to the distribution's package:

```
apt-cache policy openvpn                   # shows the distribution's version
sudo apt install --allow-downgrades openvpn=<that version>
```

## Typical routine

```
cd ../openvpn-sni-wt-my-master
dev-tools/rebuild-my-master.sh --sync --rebase-topics
dev-tools/build-deb.sh
# copy scratch/deb/openvpn_*.deb to the servers, install, restart
```

After changes to the C code, also rebuild the Android client (ics-openvpn)
in its own project.
