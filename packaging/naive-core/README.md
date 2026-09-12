# Vendored `naive`

`Profile.Protocol == "naive"` routes egress through the [NaiveProxy](https://github.com/klzgrad/naiveproxy)
client (`naive`) as a sidecar next to Xray, instead of an Xray outbound --
see [`docs/HANDOFF-naive.md`](../../docs/HANDOFF-naive.md) for why. Unlike
xray-core, `naive` isn't in any Entware feed and this project doesn't
compile it: klzgrad already publishes ready binaries for our
architectures, so this package just re-hosts one of those under this
repo's own releases, the same trust shape as `xray-core/<tag>`.

## The pin

`version` in this directory holds the klzgrad/naiveproxy release this
project has mirrored and smoke-tested -- currently:

```
v150.0.7871.63-1
```

It must match `naivecore.PinnedVersion` (a test enforces this). Unlike
xray-core there's no separate "default vs opt-in prerelease" split --
naive itself is entirely opt-in (only fetched once a naive profile
exists, or via `keenetic-xray internal ensure-naive-core`), so there's
just the one pin. Bump it by running the mirror workflow (below) for the
new version, confirming it's green, then updating this file together
with `naivecore.PinnedVersion` in the same PR.

## Mirroring

The `Naive-core build` GitHub Actions workflow (`workflow_dispatch`,
input: the klzgrad release tag) downloads, per arch (`arm64`, `mipsle`):

```
https://github.com/klzgrad/naiveproxy/releases/download/<ver>/naiveproxy-<ver>-openwrt-<target>.tar.xz
```

using the **static** openwrt builds (`aarch64_generic-static` /
`mipsel_24kc-static`) specifically -- they carry no libc dependency,
which sidesteps any question of whether Entware's libc matches what the
binary was linked against. It extracts the `naive` binary, UPX-packs it
(`--lzma` for arm64; NRV for mipsle, same as xray-core -- UPX's LZMA path
doesn't cover mips ELF), keeps a plain `.xz` of the unpacked binary as a
fallback, and uploads to a release tagged `naive-core/<ver>`:

| asset | what |
|---|---|
| `naive-<ver>-linux-<arch>` | UPX-packed, runs directly |
| `naive-<ver>-linux-<arch>.xz` | plain `xz` of the unpacked binary -- fallback if the UPX build won't `exec` on a given router |
| `naive-<ver>-linux-<arch>.sha256` | checksums for both |
| `naive-<ver>-linux-<arch>.provenance.txt` | upstream URL, both sha256s, the klzgrad/Chromium version |

## Trust

The binary is third-party (klzgrad/naiveproxy, BSD-3-Clause, itself built
on Chromium's net stack); this repo only re-hosts what klzgrad already
publishes, unmodified. klzgrad doesn't publish per-asset checksums, so
the provenance file instead records the exact upstream asset URL and the
sha256 *this workflow computed* of what it downloaded from there --
anyone can re-fetch that same URL and confirm it matches. `naivecore.Ensure`
verifies the vendored binary it downloads against the sha256 this repo's
own release publishes alongside it, and smoke-tests it (`naive --version`)
in a temp file before it's ever swapped into place -- there is no opkg or
other fallback if that fails, since naive isn't available any other way
on this platform.

## License

naiveproxy is BSD-3-Clause: <https://github.com/klzgrad/naiveproxy/blob/master/LICENSE>
(it vendors Chromium's net stack, itself BSD-3-Clause). Redistribution of
the compiled binary is permitted; the source is the upstream repo at the
pinned release.
