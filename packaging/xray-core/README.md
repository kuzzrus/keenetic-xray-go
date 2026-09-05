# Vendored Xray-core

`.ipk` installs list `xray-core` from the Entware feed as a dependency,
but that feed doesn't always carry a current `xray-core` for both router
architectures, and on a small internal-flash `/opt` its download + unpack
can be too large. So the installer can instead fetch a size-optimised
`xray` binary built from a pinned upstream tag and published to this
repo's releases.

## The pin, and the opt-in

`version` in this directory holds the **default** XTLS/Xray-core tag the
installer fetches — currently:

```
v26.3.27
```

It's the last non-prerelease upstream release at the time of writing, and
it must match `xraycore.DefaultTag` (a test enforces this). Bump it
together with a `keenetic-xray` release, then run the build (below) for
the new tag.

A **second**, newer tag can be built and offered as an explicit opt-in
without becoming the default — `xraycore.PrereleaseTag` (currently
`v26.7.28`, an upstream *pre-release*). A router runs it only if asked:

- at install: `curl … | sh -s -- --xray-core-tag=v26.7.28`
- later, over SSH: `keenetic-xray internal ensure-xray-core --tag=v26.7.28`
- from the bot: `🧩 Ядро xray` on the router card, or `/update_core
  <router> v26.7.28`

The choice is stored in `config.json` as `xray_core_tag`, so a package
self-update keeps it. `--tag=stable` (or the bot's *Стабильное* button)
clears it back to the default pin. Both tags must have a published
`xray-core/<tag>` release before they're referenced, or the fetch 404s
(the running core is left untouched — `ensure-xray-core` smoke-tests the
download in a temp file before swapping it in).

## Building

The `Xray-core build` GitHub Actions workflow (`workflow_dispatch`,
input: the tag — run it once per tag you want available, default or
opt-in) checks out `XTLS/Xray-core` at that tag and, per arch
(`arm64`, `mipsle` softfloat):

```
CGO_ENABLED=0 GOOS=linux GOARCH=<arch> GOMIPS=<gomips> GOFLAGS=-trimpath \
  go build -ldflags "-s -w -buildid=" -o xray ./main
upx -9 [--lzma]   # --lzma for arm64; NRV for mipsle (UPX LZMA doesn't cover mips ELF)
```

and uploads to a release tagged `xray-core/<tag>`:

| asset | what |
|---|---|
| `xray-<tag>-linux-<arch>` | UPX-packed, runs directly (decompresses into memory at `exec`) |
| `xray-<tag>-linux-<arch>.xz` | plain `xz` of the unpacked binary — fallback if the UPX build won't `exec` on a given router |
| `xray-<tag>-linux-<arch>.sha256` | checksums for both |
| `xray-<tag>-linux-<arch>.provenance.txt` | tag, commit, build flags, Go version, UPX version, sizes, both sha256s |

## Trust

The binary is third-party (XTLS/Xray-core, MPL-2.0); this repo only
rebuilds and re-hosts it. `-trimpath -buildid=` plus the pinned source
and Go version make the build close to reproducible; the provenance file
records everything needed to check it. The installer verifies the
downloaded asset against its published sha256 before use, and falls back
to `opkg install xray-core` if the asset can't be fetched or verified.

## License

Xray-core is MPL-2.0: <https://github.com/XTLS/Xray-core/blob/main/LICENSE>.
Redistribution of the compiled binary is permitted; the source is the
upstream repo at the pinned tag.
