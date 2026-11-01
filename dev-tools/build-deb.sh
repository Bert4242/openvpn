#!/bin/bash
#
# Build a .deb of the checked-out commit (typically my-master) that installs
# in place of the distribution's "openvpn" package.
#
#   dev-tools/build-deb.sh [--out DIR] [--check]
#
#   --out DIR   where the build happens and the .deb lands
#               (default: scratch/deb in the checkout)
#   --check     also run "make check" before packaging
#
# How: the commit is built with the same configure options as Debian's
# package, then the distribution's own openvpn .deb (fetched with
# "apt-get download") is taken as a template and only its binaries, plugins,
# headers and man pages are replaced.  Everything else is kept exactly as the
# distribution ships it: systemd units (openvpn@, openvpn-server@,
# openvpn-client@), the generator, /etc/default/openvpn, maintainer scripts,
# conffiles.  So an existing setup keeps working unchanged after the install.
#
# The .deb is for the distribution and release of the machine that builds it
# (library versions differ between releases): build on a Debian 13 host for
# Debian 13 servers, on Ubuntu 24.04 for Ubuntu 24.04, and so on.
#
# Version: <upstream>~git<commit date>+<commit>+<distro>, for example
#   2.8~git202611011905.1b84104d+deb13
# It sorts above the distribution's 2.6.x, so apt does not replace it with a
# distribution update, and later my-master builds sort above earlier ones.
#
# Installing it does not restart running VPNs (the distribution's maintainer
# scripts don't on upgrade); restart them when convenient, e.g.
#   systemctl restart openvpn-server@NAME   or   openvpn@NAME

set -eu

out=""
check=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out=$2; shift ;;
        --check) check=1 ;;
        -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

top=$(git rev-parse --show-toplevel)
if [ -z "$out" ]; then
    out="$top/scratch/deb"
else
    : # explicit --out
fi
if [ -n "$(git -C "$top" status --porcelain --untracked-files=no)" ]; then
    echo "working tree has uncommitted changes: commit them first," >&2
    echo "the package is built from the commit, not the working tree" >&2
    exit 1
else
    : # clean
fi

# --- build dependencies -----------------------------------------------------
need_pkgs=(build-essential autoconf automake libtool pkg-config python3-docutils
    libssl-dev liblzo2-dev liblz4-dev libpam0g-dev libpkcs11-helper1-dev
    libcap-ng-dev libnl-genl-3-dev libsystemd-dev dpkg-dev)
if [ "$check" = 1 ]; then
    need_pkgs+=(libcmocka-dev)
else
    : # unit tests not run: cmocka not needed
fi
missing=()
for p in "${need_pkgs[@]}"; do
    if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then
        : # present
    else
        missing+=("$p")
    fi
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "missing build dependencies; install them with:" >&2
    echo "  sudo apt-get install ${missing[*]}" >&2
    exit 1
else
    : # all there
fi

# --- source -----------------------------------------------------------------
sha=$(git -C "$top" rev-parse HEAD)
short=$(git -C "$top" rev-parse --short=8 HEAD)
branch=$(git -C "$top" symbolic-ref --quiet --short HEAD || echo detached)
cdate=$(TZ=UTC git -C "$top" log -1 --date=format-local:%Y%m%d%H%M --format=%cd HEAD)

. /etc/os-release
case "$ID" in
    debian) dist="deb${VERSION_ID%%.*}" ;;
    ubuntu) dist="ubuntu${VERSION_ID}" ;;
    *) dist="${ID}${VERSION_ID:-}" ;;
esac
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
arch=$(dpkg --print-architecture)

major=$(sed -n 's/^define(\[PRODUCT_VERSION_MAJOR\], \[\(.*\)\])/\1/p' "$top/version.m4")
minor=$(sed -n 's/^define(\[PRODUCT_VERSION_MINOR\], \[\(.*\)\])/\1/p' "$top/version.m4")
patch=$(sed -n 's/^define(\[PRODUCT_VERSION_PATCH\], \[\(.*\)\])/\1/p' "$top/version.m4")
case "$patch" in
    _git) upver="$major.$minor~git$cdate.$short" ;;      # development tree
    .*) upver="$major.$minor$patch+git$cdate.$short" ;;  # release branch
    *) upver="$major.$minor~$patch.git$cdate.$short" ;;  # _beta1, _rc2, ...
esac
version="$upver+$dist"
echo "building openvpn $version from $branch $short"

rm -rf "$out/src" "$out/stage" "$out/pkg" "$out/template"
mkdir -p "$out"
# a real clone, so the build embeds branch/commit in "openvpn --version"
git clone -q --shared --no-checkout "$top" "$out/src"
git -C "$out/src" checkout -q -B "$branch" "$sha"

# --- build ------------------------------------------------------------------
(
    cd "$out/src"
    autoreconf -fi >/dev/null 2>&1
    # the options of Debian's package (see "openvpn --version" there)
    ./configure -q \
        --prefix=/usr --sysconfdir=/etc --localstatedir=/var --runstatedir=/run \
        --libdir="/usr/lib/$multiarch" \
        --with-plugindir="/usr/lib/$multiarch/openvpn/plugins" \
        --enable-systemd --enable-pkcs11 --enable-x509-alt-username \
        --with-crypto-library=openssl \
        CFLAGS="$(dpkg-buildflags --get CFLAGS)" \
        CPPFLAGS="$(dpkg-buildflags --get CPPFLAGS)" \
        LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"
    make -s -j"$(nproc)"
    if [ "$check" = 1 ]; then
        make -s check -j"$(nproc)"
    else
        : # not asked for
    fi
    make -s install DESTDIR="$out/stage" >/dev/null
)
"$out/stage/usr/sbin/openvpn" --version | head -1

# --- template: the distribution's own package --------------------------------
mkdir -p "$out/template"
(cd "$out/template" && apt-get download openvpn >/dev/null)
tdeb=$(ls "$out/template"/openvpn_*.deb)
dpkg-deb -R "$tdeb" "$out/pkg"
pkg="$out/pkg"
echo "template: $(basename "$tdeb")"

# --- replace binaries, plugins, headers and man pages ------------------------
install -m 0755 "$out/stage/usr/sbin/openvpn" "$pkg/usr/sbin/openvpn"
plugdir="usr/lib/$multiarch/openvpn/plugins"
mkdir -p "$pkg/$plugdir"
for so in "$out/stage/$plugdir"/*.so; do
    install -m 0644 "$so" "$pkg/$plugdir/"
done
# upstream installs them in /usr/include, Debian in /usr/include/openvpn
for h in "$out/stage/usr/include"/openvpn-*.h; do
    install -D -m 0644 "$h" "$pkg/usr/include/openvpn/$(basename "$h")"
done
for man in "$out/stage/usr/share/man"/man*/*; do
    sect=$(basename "$(dirname "$man")")
    mkdir -p "$pkg/usr/share/man/$sect"
    gzip -9n -c "$man" >"$pkg/usr/share/man/$sect/$(basename "$man").gz"
done
strip --strip-unneeded --remove-section=.comment --remove-section=.note \
    "$pkg/usr/sbin/openvpn" "$pkg/$plugdir"/*.so

# what this build is, for whoever finds it installed on a server
doc="$pkg/usr/share/doc/openvpn"
mkdir -p "$doc"
{
    echo "This openvpn package is a local build, not the distribution's."
    echo
    echo "version:  $version"
    echo "source:   $branch $sha"
    echo "describe: $(git -C "$top" describe --tags --always "$sha")"
    echo "template: $(basename "$tdeb") (packaging, units and scripts kept)"
    echo "built:    $(date -u +%Y-%m-%dT%H:%MZ) on $(hostname)"
    echo
    echo "branches merged on top of master:"
    git -C "$top" log --first-parent --merges --format='  %s' "$sha" -- 2>/dev/null \
        | grep "into $branch" || echo "  (none found)"
} >"$doc/README.local-build"

# --- control file ------------------------------------------------------------
# library dependencies of the new binaries (dpkg-shlibdeps wants a
# debian/control next to it; give it a minimal one in the build dir)
mkdir -p "$out/shlibs/debian"
printf 'Source: openvpn\n\nPackage: openvpn\nArchitecture: any\n' >"$out/shlibs/debian/control"
shlibdeps=$(cd "$out/shlibs" \
    && dpkg-shlibdeps -O "$pkg/usr/sbin/openvpn" "$pkg/$plugdir"/*.so 2>/dev/null \
    | sed -n 's/^shlibs:Depends=//p')
if [ -z "$shlibdeps" ]; then
    echo "dpkg-shlibdeps found no dependencies, something is wrong" >&2
    exit 1
else
    : # got them
fi
# keep the template's non-library dependencies (debconf)
otherdeps=$(sed -n 's/^Depends: //p' "$pkg/DEBIAN/control" | tr ',' '\n' \
    | sed 's/^ *//' | grep -i debconf | paste -sd, - | sed 's/,/, /g')
if [ -n "$otherdeps" ]; then
    depends="$otherdeps, $shlibdeps"
else
    depends="$shlibdeps"
fi
size=$(du -k -s --exclude=DEBIAN "$pkg" | cut -f1)
maint="$(git -C "$top" config user.name || echo local) <$(git -C "$top" config user.email || echo root@localhost)>"
sed -i \
    -e "s/^Version: .*/Version: $version/" \
    -e "s/^Depends: .*/Depends: $depends/" \
    -e "s/^Installed-Size: .*/Installed-Size: $size/" \
    -e "s/^Maintainer: .*/Maintainer: $maint/" \
    "$pkg/DEBIAN/control"
sed -i "/^Description:/s/\$/ (local build of $branch $short)/" "$pkg/DEBIAN/control"

(cd "$pkg" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' \
    | sort -z | xargs -0 md5sum) >"$pkg/DEBIAN/md5sums"

deb="$out/openvpn_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >/dev/null
echo
echo "built $deb"
echo "install with:  sudo apt install ./$(basename "$deb")"
echo "back to the distribution's package:  sudo apt install --allow-downgrades openvpn=<its version>"
echo "restart the VPNs afterwards (installing does not restart them)."
