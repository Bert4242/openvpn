#!/bin/bash
#
# Rebuild the "my-master" integration branch: the current master plus the
# local topic branches, merged in order.  Run it after master was updated.
#
#   dev-tools/rebuild-my-master.sh [--no-push]
#
# What it does:
#   1. fetches origin;
#   2. starts a fresh my-master from origin/master;
#   3. merges each topic branch of TOPICS (origin/<topic>) with a merge commit;
#   4. tags the result my-master-YYYY-MM-DD (.2, .3, ... for later rebuilds
#      the same day), so every earlier build stays reachable;
#   5. force-pushes my-master (with lease) and pushes the tag, unless --no-push.
#
# my-master is derived and rebuilt from scratch every time: never commit on it
# directly.  Fix things on the topic branches (or add a new topic to TOPICS).
#
# Conflicts: git rerere is turned on, so a conflict resolved once is replayed
# automatically on later rebuilds.  When a merge stops on a new conflict, the
# script exits and leaves the merge in progress: resolve it, "git commit",
# then run the script again (rerere has recorded the resolution).
#
# Must run in a checkout that is on my-master or a detached HEAD with a clean
# tree, typically the dedicated worktree ../openvpn-sni-wt-my-master.

set -eu

BASE=origin/master
# merge order matters: multi-listener-2 is built on sni-gateway-modes-6
TOPICS=(
    sni-gateway-modes-6
    multi-listener-2
    ignore-cert-expiry
    my-master-tools
)
BRANCH=my-master

push=1
for arg in "$@"; do
    case "$arg" in
        --no-push) push=0 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
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

git checkout -q -B "$BRANCH" "$BASE"
echo "base: $(git log --oneline -1 "$BASE")"

for topic in "${TOPICS[@]}"; do
    ref="origin/$topic"
    if ! git rev-parse --verify --quiet "$ref" >/dev/null; then
        echo "topic branch $ref does not exist, aborting" >&2
        exit 1
    else
        : # topic exists
    fi
    if git merge-base --is-ancestor "$ref" HEAD; then
        echo "= $topic: already contained"
        continue
    else
        : # needs a merge
    fi
    if git merge --no-ff --no-edit -m "Merge $topic into $BRANCH" "$ref" >/dev/null; then
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
git tag -a "$tag" -m "$BRANCH built from $(git rev-parse --short "$BASE") + ${TOPICS[*]}"
echo "tagged $tag"

if [ "$push" = 1 ]; then
    git push --force-with-lease origin "$BRANCH"
    git push origin "refs/tags/$tag"
else
    echo "not pushed (--no-push)"
fi
