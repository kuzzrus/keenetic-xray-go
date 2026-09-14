# Vendored `susanin-agent`

The `susanin` addon (`internal/addons`) wraps [Susanin.Keenetic](https://github.com/R17a/Susanin.Keenetic)
-- adaptive, conntrack-based blocked-destination routing that runs
*alongside* xray, pointed at our WG-transport interface -- see
[`docs/HANDOFF-susanin.md`](../../docs/HANDOFF-susanin.md) (Phase 1 of the
plan). Susanin isn't in any Entware feed and this project doesn't build it:
upstream already publishes a ready per-arch release tarball, so this
package just re-hosts a verified copy of one of those under this repo's
own releases -- the same trust shape as `naive-core`, except the asset is
a tarball (binary + upstream's own install/control scripts + default
lists), not a bare binary, and it's re-hosted **unmodified** rather than
UPX-repacked (see "Mirroring" below for why).

## The pin

`version` in this directory holds the R17a/Susanin.Keenetic release this
project has mirrored and smoke-tested -- currently:

```
v0.3.8
```

It must match `susanincore.PinnedVersion` (a test enforces this). Bump it
by running the mirror workflow (below) for the new version, confirming
it's green, then updating this file together with
`susanincore.PinnedVersion` in the same PR.

## Mirroring

The `Susanin-core build` GitHub Actions workflow (`workflow_dispatch`,
input: the upstream release tag) downloads, per arch (`arm64` from
upstream's `aarch64`, `mipsle` from upstream's `mipsel`):

```
https://github.com/R17a/Susanin.Keenetic/releases/download/<ver>/susanin-keenetic-deploy-<upstream-arch>.tar.gz
```

verifies it against upstream's own `SHA256SUMS`, extracts it, and re-tars
the whole thing (upstream's own `install.sh`/`susanin.sh`/`datapath.sh`/
`update.sh`/`uninstall.sh`, `config.example.conf`, `vpn_always.txt`,
`vpn_never.txt`, `susanin-agent`) unmodified into a release tagged
`susanin/<ver>`:

| asset | what |
|---|---|
| `susanin-<ver>-linux-<arch>.tar.gz` | upstream's own tarball layout, byte-for-byte (re-tarred, not re-encoded) |
| `susanin-<ver>-linux-<arch>.tar.gz.sha256` | checksum, as packaged by this workflow |
| `susanin-<ver>-linux-<arch>.provenance.txt` | upstream URL, upstream's own sha256, binary size/sha256 |

**Not UPX-packed**, unlike xray-core/naive-core: `susanin-agent` is
already small (827 KB unpacked for mipsel v0.3.6), and an actual attempt
at it hit a real compatibility problem -- `upx --lzma` on the aarch64
build produced a SIGILL under `qemu-aarch64-static` specifically (plain
UPX on mipsel packed and ran fine), caught by dispatching the workflow for
real rather than assumed. Not worth chasing down for the size this
particular binary would save.

## Trust

The binary is third-party (R17a/Susanin.Keenetic, MIT); this repo only
re-hosts what upstream already publishes, unmodified -- verified against
upstream's own `SHA256SUMS` before re-tarring, and the provenance file
records the exact upstream asset URL and hash so anyone can re-fetch and
confirm. `susanincore.Ensure` verifies the tarball it downloads against
the sha256 this repo's own release publishes alongside it, and
smoke-tests the extracted binary (`susanin-agent version`) before handing
it back anywhere persistent -- no opkg or other fallback if that fails,
since Susanin isn't available any other way on this platform.

## License

Susanin.Keenetic is MIT: <https://github.com/R17a/Susanin.Keenetic/blob/main/LICENSE>.
Redistribution of the tarball, unmodified, is permitted; the source is the
upstream repo at the pinned release.
