// Package opkg installs Entware packages and, when that fails, says why in
// words an operator can act on.
//
// Four places used to run `opkg update; opkg install <pkg>` on their own
// (ipset, conntrack, iptables, cron) and report a failure as the bare exit
// status of the second command -- "installing ipset via opkg: exit status 255"
// -- which tells someone who has never used opkg nothing: no network, no
// space on the drive, another opkg already running, and a package missing from
// the feed all look the same. They all go through Install now, and its error
// carries the end of opkg's own output and a plain-language reason when the
// output matches a known cause.
package opkg

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// run executes `opkg <args...>` and returns its combined output. A variable so
// tests can stand in for opkg.
var run = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "opkg", args...).CombinedOutput()
}

// Install runs `opkg update` and then `opkg install pkgs...`.
//
// The update is best-effort: a router that has never run it has an empty
// package index, and then `opkg install` answers "Unknown package" for a
// package the feed does have; but a failed update is not itself a failure --
// the index may be fresh already. Its output is still kept, because when the
// install then fails, "Failed to download" in the update's output is the real
// reason.
func Install(ctx context.Context, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	updOut, updErr := run(ctx, "update")
	if updErr == nil || len(strings.TrimSpace(string(updOut))) == 0 {
		updOut = nil // nothing worth keeping: it worked, or it said nothing
	} else {
		updOut = append([]byte("opkg update failed: "), updOut...)
	}
	return install(ctx, pkgs, updOut)
}

// InstallNoUpdate is Install without the `opkg update`: for retrying one
// package after a joint install failed, when the index was refreshed a moment
// ago.
func InstallNoUpdate(ctx context.Context, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	return install(ctx, pkgs, nil)
}

func install(ctx context.Context, pkgs []string, earlier []byte) error {
	out, err := run(ctx, append([]string{"install"}, pkgs...)...)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	all := string(earlier) + string(out)
	return &Error{Pkgs: pkgs, Reason: Explain(all, err), Output: tail(all), Err: err}
}

// Error is a failed install. Reason is a sentence for the operator ("" when
// the output matched nothing known); Output is the last lines opkg printed.
type Error struct {
	Pkgs   []string
	Reason string
	Output string
	Err    error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("opkg install " + strings.Join(e.Pkgs, " ") + ": ")
	if e.Reason != "" {
		b.WriteString(e.Reason)
	} else {
		b.WriteString(e.Err.Error())
	}
	if e.Output != "" {
		b.WriteString(" [" + e.Output + "]")
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Explain maps what opkg printed (and the error from running it) to a reason
// in plain Russian, or "" when it is not a cause it knows. The checks run in
// order of how misleading the later messages would be: a failed `opkg update`
// makes the install report "Unknown package", so the network is tested before
// the package index.
func Explain(output string, err error) string {
	low := strings.ToLower(output)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(low, strings.ToLower(s)) {
				return true
			}
		}
		return false
	}
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return "opkg не найден — Entware не установлен или накопитель с /opt не подключён"
	case has("could not lock", "opkg.lock", "resource temporarily unavailable"):
		return "opkg занят другим процессом (идёт установка или обновление) — подожди минуту и повтори"
	case has("no space left", "not enough free space", "write error", "disk full"):
		return "на накопителе с /opt нет свободного места"
	case has("ssl support not available", "not an http or ftp url", "ssl_client", "libustream"):
		return "wget на роутере не умеет HTTPS — поставь ca-certificates и wget-ssl"
	case has("failed to download", "could not resolve", "bad address", "network is unreachable",
		"connection refused", "connection timed out", "operation timed out", "download failed",
		"wget returned", "no route to host", "temporary failure in name resolution"):
		return "нет связи с репозиторием Entware — проверь интернет и DNS на роутере"
	case has("unknown package", "cannot find package", "no packages found"):
		return "такого пакета нет в репозитории Entware для этой платформы (или список пакетов не обновился)"
	case has("cannot satisfy the following dependencies", "unsatisfied dependencies", "pkg_hash_check_unresolved"):
		return "не хватает пакетов, от которых зависит этот"
	case errors.Is(err, context.DeadlineExceeded):
		return "не уложился во время — медленная связь с репозиторием, повтори позже"
	case errors.Is(err, context.Canceled):
		return "установка прервана"
	}
	return ""
}

// tail is the last few lines of output, joined for one line of an error
// message and cut to a length that still fits a chat message.
func tail(s string) string {
	const maxLines, maxLen = 3, 300
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	out := strings.Join(lines, " | ")
	if len(out) > maxLen {
		out = "…" + out[len(out)-maxLen:]
	}
	return out
}
