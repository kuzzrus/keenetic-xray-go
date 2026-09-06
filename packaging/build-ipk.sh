#!/bin/sh
# build-ipk.sh -- hand-rolled .ipk builder, fallback for when goreleaser's
# nfpm integration doesn't produce something real opkg accepts (M7 spike,
# not yet verified).
#
# The .ipk format here is a single gzip-compressed tar containing
# "./debian-binary", "./data.tar.gz", and "./control.tar.gz" -- NOT an
# `ar` archive. That assumption (ipk == the ar-wrapped .deb format) was
# wrong and cost three failed real-hardware install attempts to find:
# `ar t` on a real Entware-served .ipk (xray-core's own package,
# downloaded directly from bin.entware.net) fails with "invalid ar
# magic", while `tar tzf` on the same file lists the three members
# directly and its first bytes are the plain gzip magic (1f 8b). This
# script now matches that exact reference file byte-for-byte in
# structure (including member order: debian-binary, data.tar.gz,
# control.tar.gz, not the alphabetical/`ar`-conventional order used
# earlier). Confirmed on real hardware. Do not "fix" this back to an ar
# archive without re-confirming against a real Entware-served .ipk --
# every ar-based attempt looked individually correct (byte-verified,
# even matched a real `dpkg-deb --build` reference archive) and every
# one was still rejected, because the container format itself was wrong.
#
# The release workflow UPX-packs <binary-path> in place before calling
# this script, so the shipped .ipk carries a ~2.5-4MB binary. Running
# this by hand on an unpacked binary just yields a larger .ipk -- still
# valid, opkg doesn't care.
#
# Usage: build-ipk.sh <version> <arch> <binary-path> <output.ipk>
# Example:
#   build-ipk.sh 0.1.0-1 aarch64-3.10 dist/keenetic-xray-linux-arm64 \
#     dist/keenetic-xray_0.1.0-1_aarch64-3.10.ipk
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <version> <arch> <binary-path> <output.ipk>" >&2
    exit 1
fi

PKG_NAME="keenetic-xray"
PKG_VERSION="$1"
PKG_ARCH="$2"
BINARY_PATH="$3"
OUTPUT="$4"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

case "$OUTPUT" in
    /*) OUTPUT_ABS="$OUTPUT" ;;
    *) OUTPUT_ABS="$(pwd)/$OUTPUT" ;;
esac
BINARY_DIR="$(CDPATH= cd -- "$(dirname -- "$BINARY_PATH")" && pwd)"
BINARY_ABS="$BINARY_DIR/$(basename -- "$BINARY_PATH")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/control"
sed \
    -e "s/{{VERSION}}/$PKG_VERSION/" \
    -e "s/{{ARCH}}/$PKG_ARCH/" \
    "$SCRIPT_DIR/ipk/control.tmpl" > "$WORK/control/control"
cp "$SCRIPT_DIR/ipk/postinst" "$WORK/control/postinst"
cp "$SCRIPT_DIR/ipk/prerm" "$WORK/control/prerm"
chmod 0755 "$WORK/control/postinst" "$WORK/control/prerm"
# Archive "." from inside the staging dir (not the bare filenames) so
# every member is indexed as "./control", "./postinst", etc., matching
# the real reference .ipk's own control.tar.gz layout.
tar --owner=0 --group=0 --numeric-owner -czf "$WORK/control.tar.gz" \
    -C "$WORK/control" .

mkdir -p "$WORK/data/opt/sbin" "$WORK/data/opt/etc/init.d" "$WORK/data/opt/etc/ndm/netfilter.d"
cp "$BINARY_ABS" "$WORK/data/opt/sbin/$PKG_NAME"
chmod 0755 "$WORK/data/opt/sbin/$PKG_NAME"
cp "$SCRIPT_DIR/init.d/S99keenetic-xray" "$WORK/data/opt/etc/init.d/S99keenetic-xray"
chmod 0755 "$WORK/data/opt/etc/init.d/S99keenetic-xray"
# ndm runs this on every firewall rebuild -> SIGUSR1 the daemon so it
# re-asserts its Proxy0 / MSS / routes / WG config immediately instead of
# waiting for the 2-minute reconcile tick. opkg removes it with the package.
cp "$SCRIPT_DIR/ndm/netfilter.d/50-keenetic-xray.sh" "$WORK/data/opt/etc/ndm/netfilter.d/50-keenetic-xray.sh"
chmod 0755 "$WORK/data/opt/etc/ndm/netfilter.d/50-keenetic-xray.sh"
tar --owner=0 --group=0 --numeric-owner -czf "$WORK/data.tar.gz" \
    -C "$WORK/data" .

echo "2.0" > "$WORK/debian-binary"

rm -f "$OUTPUT_ABS"
# Explicit "./"-prefixed args, in this exact order, so the archive's
# member names and ordering match the real reference .ipk exactly
# rather than whatever tar's own directory-scan order would produce.
tar --owner=0 --group=0 --numeric-owner -czf "$OUTPUT_ABS" \
    -C "$WORK" ./debian-binary ./data.tar.gz ./control.tar.gz

echo "built $OUTPUT_ABS"
