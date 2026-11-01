#!/bin/bash
#
# Rebuild the "my-master" integration branch: the current master plus the
# local topic branches, merged in order.  Run it after master was updated.
#
#   dev-tools/rebuild-my-master.sh [--sync] [--rebase-topics] [--no-push]
#
#   --sync           first fast-forward the fork's master to upstream/master
#                    (the OpenVPN/openvpn repository); refuses if the fork's
#                    master has commits of its own
#   --rebase-topics  also rebase every topic branch onto its new base (master,
#                    or the topic it is built on) and force-push it, so the
#                    topic branches themselves stay current, not only my-master
#   --no-push        do everything locally, push nothing and leave the local
#                    topic branches alone (a dry run of the whole update)
#
# What it does:
#   1. fetches origin (and upstream with --sync);
#   2. with --sync, fast-forwards master;
#   3. with --rebase-topics, rebases each topic onto its base, in TOPICS order;
#   4. starts a fresh my-master from master;
#   5. merges each topic branch of TOPICS with a merge commit;
#   6. tags the result my-master-YYYY-MM-DD (.2, .3, ... for later rebuilds
#      the same day), so every earlier build stays reachable;
#   7. force-pushes my-master (with lease) and pushes the tag, unless --no-push.
#
# my-master is derived and rebuilt from scratch every time: never commit on it
# directly.  Fix things on the topic branches (or add a new topic to TOPICS).
#
# Conflicts: git rerere is turned on, so a conflict resolved once is replayed
# automatically on later rebuilds and rebases.  When a merge or a rebase stops
# on a new conflict, the script exits and leaves it in progress: resolve it,
# then "git commit" (merge) or "git add" + "git rebase --continue" (rebase),
# and run the script again with the same options (rerere has recorded the
# resolution, and nothing was pushed yet).
#
# Must run in a checkout that is on my-master or a detached HEAD with a clean
# tree, typically the dedicated worktree ../openvpn-sni-wt-my-master.

set -eu

# The checkout is reset to $BASE below, which removes or replaces this very
# file while bash is still reading it: run from a copy in the git directory.
if [ -z "${REBUILD_MY_MASTER_COPY:-}" ]; then
    copy="$(git rev-parse --git-dir)/rebuild-my-master.sh"
    cp "$0" "$copy"
    REBUILD_MY_MASTER_COPY=1 exec bash "$copy" "$@"
else
    : # already running from the copy
fi

MASTER=master
UPSTREAM_REMOTE=upstream
# "topic:base" pairs, in merge order.  base is master or an earlier topic:
# multi-listener-2 is built on sni-gateway-modes-6, so it comes after it.
TOPICS=(
    sni-gateway-modes-6:master
    multi-listener-2:sni-gateway-modes-6
    ignore-cert-expiry:master
    my-master-tools:master
)
BRANCH=my-master

push=1
sync=0
rebase=0
for arg in "$@"; do
    case "$arg" in
        --no-push) push=0 ;;
        --sync) sync=1 ;;
        --rebase-topics) rebase=1 ;;
        -h|--help) sed -n '2,38p' "$0"; exit 0 ;; # $0 is the copy: same text
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

current=$(git symbolic-ref --quiet --short HEAD || echo "(detached)")
if [ "$current" != "$BRANCH" ] && [ "$current" != "(detached)" ]; then
    echo "run this on $BRANCH (or a detached HEAD), not on '$current':" >&2
    echo "it resets the checked-out branch.  Use the my-master worktree." >&2
    exit 1
else
    : # on my-master, or detached: safe to reset
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "working tree has uncommitted changes, aborting" >&2
    exit 1
else
    : # clean
fi

git config rerere.enabled true
git config rerere.autoupdate true

git fetch --prune origin

# --- 1. master --------------------------------------------------------------
BASE="origin/$MASTER"
if [ "$sync" = 1 ]; then
    git fetch "$UPSTREAM_REMOTE" "$MASTER"
    up="$UPSTREAM_REMOTE/$MASTER"
    if git merge-base --is-ancestor "$up" "$BASE"; then
        echo "master: already up to date with $up"
    elif git merge-base --is-ancestor "$BASE" "$up"; then
        echo "master: $(git rev-list --count "$BASE..$up") new commit(s) from $up"
        if [ "$push" = 1 ]; then
            git push origin "$up:refs/heads/$MASTER"
            git fetch origin "$MASTER"
        else
            BASE="$up" # not pushed: build on upstream directly
        fi
    else
        echo "origin/$MASTER has commits that are not in $up:" >&2
        git log --oneline "$up..$BASE" | sed 's/^/    /' >&2
        echo "it cannot be fast-forwarded; sort that out by hand" >&2
        exit 1
    fi
else
    : # use origin/master as it is
fi
base_sha=$(git rev-parse "$BASE")
echo "base: $(git log --oneline -1 "$base_sha")"

# --- 2. topic tips ----------------------------------------------------------
declare -A OLD NEW
for pair in "${TOPICS[@]}"; do
    topic=${pair%%:*}
    ref="origin/$topic"
    if ! git rev-parse --verify --quiet "$ref" >/dev/null; then
        echo "topic branch $ref does not exist, aborting" >&2
        exit 1
    else
        OLD[$topic]=$(git rev-parse "$ref")
        NEW[$topic]=${OLD[$topic]}
    fi
done

# Continue a rebase that stopped only on conflicts rerere has resolved.
finish_rebase()
{
    local gitdir
    gitdir=$(git rev-parse --git-dir)
    while [ -d "$gitdir/rebase-merge" ] || [ -d "$gitdir/rebase-apply" ]; do
        if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
            return 1
        else
            git add -u
            GIT_EDITOR=true git rebase --continue >/dev/null || true
        fi
    done
    return 0
}

if [ "$rebase" = 1 ]; then
    for pair in "${TOPICS[@]}"; do
        topic=${pair%%:*}
        tbase=${pair#*:}
        if [ "$tbase" = "$MASTER" ]; then
            old_base=$base_sha
            new_base=$base_sha
        elif [ -n "${NEW[$tbase]:-}" ]; then
            old_base=${OLD[$tbase]}
            new_base=${NEW[$tbase]}
        else
            echo "$topic: base '$tbase' must be $MASTER or an earlier topic" >&2
            exit 1
        fi
        if git merge-base --is-ancestor "$new_base" "${OLD[$topic]}"; then
            echo "= $topic: already on top of $tbase"
            continue
        else
            : # needs a rebase
        fi
        git checkout -q --detach "${OLD[$topic]}"
        if (git rebase --onto "$new_base" "$old_base" >/dev/null 2>&1 || finish_rebase) \
            && git merge-base --is-ancestor "$new_base" HEAD; then
            NEW[$topic]=$(git rev-parse HEAD)
            echo "^ $topic: rebased onto $tbase ($(git rev-list --count "$new_base..HEAD") commit(s))"
        else
            echo "! $topic: rebase conflict in:" >&2
            git diff --name-only --diff-filter=U | sed 's/^/    /' >&2
            echo "resolve, 'git add' + 'git rebase --continue' until done," >&2
            echo "then run this script again with the same options" >&2
            exit 1
        fi
    done
else
    : # topics are merged as they are
fi

# --- 3. my-master -----------------------------------------------------------
git checkout -q -B "$BRANCH" "$base_sha"

for pair in "${TOPICS[@]}"; do
    topic=${pair%%:*}
    tip=${NEW[$topic]}
    if git merge-base --is-ancestor "$tip" HEAD; then
        echo "= $topic: already contained"
        continue
    else
        : # needs a merge
    fi
    if git merge --no-ff --no-edit -m "Merge $topic into $BRANCH" "$tip" >/dev/null; then
        echo "+ $topic: merged"
    elif [ -z "$(git diff --name-only --diff-filter=U)" ]; then
        # every conflict was resolved by rerere
        git commit --no-edit -q
        echo "+ $topic: merged (conflicts resolved by rerere)"
    else
        echo "! $topic: merge conflict in:" >&2
        git diff --name-only --diff-filter=U | sed 's/^/    /' >&2
        echo "resolve, 'git commit', then run this script again" >&2
        exit 1
    fi
done

tag="$BRANCH-$(date +%Y-%m-%d)"
if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    n=2
    while git rev-parse --verify --quiet "refs/tags/$tag.$n" >/dev/null; do
        n=$((n + 1))
    done
    tag="$tag.$n"
else
    : # first build today
fi
names=()
for pair in "${TOPICS[@]}"; do
    names+=("${pair%%:*}")
done
git tag -a "$tag" -m "$BRANCH built from $(git rev-parse --short "$base_sha") + ${names[*]}"
echo "tagged $tag"

# --- 4. push ----------------------------------------------------------------
if [ "$push" = 0 ]; then
    echo "not pushed (--no-push); local topic branches left as they were"
    exit 0
else
    : # push below
fi

for pair in "${TOPICS[@]}"; do
    topic=${pair%%:*}
    if [ "${NEW[$topic]}" = "${OLD[$topic]}" ]; then
        continue
    else
        git push --force-with-lease="$topic:${OLD[$topic]}" origin "${NEW[$topic]}:refs/heads/$topic"
    fi
    # keep the local branch in step, unless a worktree has it checked out
    # (moving it under that worktree would leave its files out of date)
    local_tip=$(git rev-parse --verify --quiet "refs/heads/$topic" || true)
    holder=$(git worktree list --porcelain \
        | awk -v b="branch refs/heads/$topic" '/^worktree /{w=substr($0,10)} $0==b{print w}')
    if [ -z "$local_tip" ]; then
        : # no local branch: nothing to update
    elif [ -n "$holder" ]; then
        echo "  note: $topic is checked out in $holder; update it there with"
        echo "        git fetch && git reset --hard origin/$topic   (if it has no local work)"
    elif [ "$local_tip" = "${OLD[$topic]}" ]; then
        git branch -f "$topic" "${NEW[$topic]}"
    else
        echo "  note: local $topic differs from what was rebased; left alone"
    fi
done

git push --force-with-lease origin "$BRANCH"
git push origin "refs/tags/$tag"
