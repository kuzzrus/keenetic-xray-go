#!/bin/sh
# install.sh -- single entry point for installing keenetic-xray: detects
# this router's opkg architecture and installs the matching .ipk from
# the latest GitHub release. This is the "unified installer, auto-select
# by architecture" front door; all the real installation logic still
# lives in the .ipk itself (opkg dependency resolution, postinst) -- this
# script's only job is picking the right one of the two .ipk files and
# handing it to opkg.
#
# Usage (on the router):
#   curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh
# (curl, not wget: some routers' busybox wget can't fetch https:// at all.
#  opkg update && opkg install curl if it's missing.)
#
# Options:
#   --xray-core=vendored   force this project's size-optimised xray-core build
#   --xray-core=entware    force `opkg install xray-core` instead
#   (default: try vendored, fall back to Entware)
set -eu

REPO="kuzzrus/keenetic-xray-go"
TMP_IPK="/opt/keenetic-xray-install.ipk"

for arg in "$@"; do
    case "$arg" in
        --xray-core=*) export KEENETIC_XRAY_CORE="${arg#--xray-core=}" ;;
        *) echo "keenetic-xray: unknown option: $arg" >&2; exit 2 ;;
    esac
done

# fetch <url> [output-file] -- prints to stdout if no output file is
# given. Prefers curl over wget: confirmed on real hardware that some
# routers' built-in wget (a minimal busybox build) doesn't support HTTPS
# at all ("not an http or ftp url" for an https:// URL) while curl on
# the same device handles it fine. Falls back to wget for routers where
# it's the other way around.
fetch() {
    url="$1"
    out="${2:-}"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$out" ]; then
            curl -fsSL "$url" -o "$out"
        else
            curl -fsSL "$url"
        fi
    else
        if [ -n "$out" ]; then
            wget -q "$url" -O "$out"
        else
            wget -qO- "$url"
        fi
    fi
}

# Ask opkg itself which architecture tags it accepts, rather than
# parsing `uname -m` -- opkg's own architecture list is exactly what a
# .ipk's Architecture: field is matched against, so asking opkg directly
# can't disagree with what we actually need. `opkg print-architecture`
# prints lines of the form "arch <name> <priority>".
detect_arch() {
    archs="$(opkg print-architecture)"
    for candidate in aarch64-3.10 mipsel-3.4; do
        if echo "$archs" | grep -qw "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    echo "keenetic-xray: unsupported architecture -- this router's opkg reports:" >&2
    echo "$archs" >&2
    echo "keenetic-xray: only aarch64-3.10 and mipsel-3.4 are supported." >&2
    return 1
}

ARCH="$(detect_arch)"
echo "keenetic-xray: detected architecture $ARCH"

# Ask the GitHub API for the latest release's asset list instead of
# hardcoding a version number here -- a static URL would go stale the
# moment a new release ships, since asset filenames embed the version.
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
ASSET_URL="$(fetch "$API_URL" \
    | grep -o "\"browser_download_url\": *\"[^\"]*_${ARCH}\.ipk\"" \
    | sed -e 's/.*"\(https[^"]*\)"/\1/' \
    | head -n 1)"
if [ -z "$ASSET_URL" ]; then
    echo "keenetic-xray: could not find a .ipk for $ARCH in the latest release ($API_URL)" >&2
    exit 1
fi

echo "keenetic-xray: downloading $ASSET_URL"
fetch "$ASSET_URL" "$TMP_IPK"
opkg install "$TMP_IPK"
rm -f "$TMP_IPK"
