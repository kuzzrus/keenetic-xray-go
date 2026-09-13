# Vendored `susanin-agent`

The `susanin` addon (`internal/addons`) wraps [Susanin.Keenetic](https://github.com/R17a/Susanin.Keenetic)
-- adaptive, conntrack-based blocked-destination routing that runs
*alongside* xray, pointed at our WG-transport interface -- see
[`docs/HANDOFF-susanin.md`](../../docs/HANDOFF-susanin.md) (Phase 1 of the
plan). Susanin isn't in any Entware feed and this project doesn't build it:
upstream already publishes a ready per-arch release tarball, so this
package just re-hosts a repacked copy of one of those under this repo's
own releases -- the same trust shape as `naive-core`, except the asset is
a tarball (binary + upstream's own install/control scripts + default
lists), not a bare binary.

## The pin

`version` in this directory holds the R17a/Susanin.Keenetic release this
project has mirrored and smoke-tested -- currently:

```
v0.3.6
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

verifies it against upstream's own `SHA256SUMS`, extracts it, UPX-packs
*just* the `susanin-agent` binary in place (`--lzma` for arm64; NRV for
mipsle, same as xray-core/naive-core -- UPX's LZMA path doesn't cover mips
ELF), and re-tars the whole thing (upstream's own `install.sh`/`susanin.sh`/
`datapath.sh`/`update.sh`/`uninstall.sh`, `config.example.conf`,
`vpn_always.txt`, `vpn_never.txt`, now with the smaller binary) into a
release tagged `susanin/<ver>`:

| asset | what |
|---|---|
| `susanin-<ver>-linux-<arch>.tar.gz` | upstream's own tarball layout, `susanin-agent` UPX-packed |
| `susanin-<ver>-linux-<arch>.tar.gz.sha256` | checksum, as packed by this workflow |
| `susanin-<ver>-linux-<arch>.provenance.txt` | upstream URL, upstream's own sha256, pack details |

No separate unpacked-binary fallback is published (unlike naive-core's
`.xz`) -- upstream's own release stays available directly at the URL the
provenance file records if the UPX build ever doesn't `exec` on some
router; this is lower-stakes, opt-in addon territory, not the egress path
itself.

## Trust

The binary is third-party (R17a/Susanin.Keenetic, MIT); this repo only
re-packs what upstream already publishes -- UPX-compression is the only
change, everything else in the tarball (scripts, default config, default
`vpn_always`/`vpn_never` lists) is unmodified. Verified against upstream's
own `SHA256SUMS` before repacking; the provenance file records the exact
upstream asset URL and hash so anyone can re-fetch and confirm.
`susanincore.Ensure` verifies the tarball it downloads against the sha256
this repo's own release publishes alongside it, and smoke-tests the
packed binary (`susanin-agent version`) before extracting it anywhere
persistent -- no opkg or other fallback if that fails, since Susanin isn't
available any other way on this platform.

## License

Susanin.Keenetic is MIT: <https://github.com/R17a/Susanin.Keenetic/blob/main/LICENSE>.
Redistribution of the tarball (with the binary UPX-repacked) is permitted;
the source is the upstream repo at the pinned release.
