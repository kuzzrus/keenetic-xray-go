# Full vs Mini

**Full is the default.** Mini is an explicit opt-in
(`install.sh --mini`, or `keenetic-xray variant set mini` afterward).

Mini/Full is **not** a packaging split -- there is one `.ipk` per
architecture, always -- and it does **not** gate any feature. It's a
runtime flag (`"variant": "mini"|"full"` in `config.json`) whose only
effect is how much log/history state the daemon is willing to accumulate.

## Why it barely matters now

A stdlib-only Go binary is roughly the same size regardless of which
features are compiled in (Go statically links its runtime either way),
so there was never a binary-size axis to gate. The disk state that
*could* grow unbounded is already capped independently:

- `internal/applog` self-trims the daemon log (`DefaultMaxBytes`, ~256KB);
- failover keeps only the last ~20 transitions / ~30 health-check
  results, in memory;
- the preset overlay (`internal/presets`) is bounded by the manifest.

So in practice Mini and Full behave the same. The flag is kept because
(a) existing `config.json` files carry it, and (b) a future disk-heavy
feature could still consult it -- but nothing does today, including the
remote-control agent, which now enables on either variant.

## What used to be gated (and no longer is)

| | before | now |
|---|---|---|
| variant decision | auto, by free space on `/opt` (43MB threshold) | Full unless `--mini` |
| remote-control agent (`agent enable`) | Full only | available on both |
| `variant set mini` with agent on | force-disabled the agent | leaves it alone |

## When to pick Mini

Only if you're on a genuinely tiny storage (tens of MB free on `/opt`)
and want the daemon to keep its retention minimal. On anything with room
to spare, leave it Full.
