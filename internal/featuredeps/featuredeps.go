// Package featuredeps makes sure what a feature needs is on the router when the
// feature is switched on.
//
// Before this, only some switches did it, each in its own way: adaptive routing
// installed ipset and conntrack but not iptables, the MSS clamp installed
// iptables, the watchdog installed cron -- and L7 SNI installed nothing at all.
// Switching it on saved the setting and restarted the daemon, whose capture then
// died on its first `iptables` call with a line in the log nobody reads, and
// was never started again. An operator who has never used opkg has no way to
// guess which package was missing.
//
// Every enabling path (the CLI command, the bot button, and the daemon when it
// starts the feature) now calls Ensure with the feature and gets the same
// answer: what was installed, which optional tool could not be, and -- for a
// tool the feature cannot work without -- an error that says what to type by
// hand. The list of what each feature needs lives in one place, here.
package featuredeps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
	"github.com/kuzzrus/keenetic-xray-go/internal/opkg"
)

// Feature is a switch an operator can turn on.
type Feature string

const (
	// AdaptiveRouting: the REDIRECT rule and the address set it matches.
	AdaptiveRouting Feature = "adaptive"
	// L7SNI: the NFLOG capture of TLS/HTTP/QUIC names (and its QUIC modes).
	L7SNI Feature = "l7sni"
)

// Timeout is how long a caller should allow Ensure: a cold `opkg update` plus an
// install over a slow link takes minutes, and a command killed halfway leaves
// opkg's state for the next run to repair.
const Timeout = 3 * time.Minute

// Need is one thing a feature needs.
type Need struct {
	// Name is what the operator calls it: "ipset", "модули ядра NFLOG".
	Name string
	// Pkg is the Entware package that provides it; "" for a need that is
	// provided some other way (Provide).
	Pkg string
	// Why says what it is for, in the words the messages use.
	Why string
	// Without, when set, makes the need optional and says what stops working
	// without it. Empty: the feature cannot work.
	Without string
	// Hint is what to say when a need that is not a package cannot be provided
	// (for a package the message gives the `opkg install` command instead).
	Hint string
	// Present reports whether it is there now. nil: unknown, Provide always runs.
	Present func() bool
	// Provide makes a need that is not a package available. Runs only when
	// Present is nil or false, and must be safe to repeat.
	Provide func(ctx context.Context) error
}

// optional reports whether the feature works without the need.
func (n Need) optional() bool { return n.Without != "" }

// Failure is a need that could not be provided.
type Failure struct {
	Need Need
	Err  error
}

// Result is what Ensure did.
type Result struct {
	Feature   Feature
	Installed []Need    // were missing, are there now
	Failed    []Failure // could not be provided
}

// The points below are the only places Ensure touches the system -- variables
// so tests can run it without opkg, iptables or a kernel.
var (
	opkgInstall         = opkg.Install
	opkgInstallNoUpdate = opkg.InstallNoUpdate

	// needsFor is the catalogue: what each feature needs, in the order the
	// messages list it.
	needsFor = catalogue
)

// installMu serialises installs inside this process: the capture's start, the
// bot's button and a reconcile can reach Ensure together, and two opkg runs at
// once either fail on its lock or race over the same package.
var installMu sync.Mutex

// Missing lists the needs of f that are not there right now -- cheap probes,
// nothing is installed -- so a caller can say "installing X, this can take a
// couple of minutes" before Ensure goes quiet for that long. Needs that cannot
// be probed (the kernel modules) are not listed.
func Missing(f Feature) []Need {
	var out []Need
	for _, n := range needsFor(f) {
		if n.Present != nil && !n.Present() {
			out = append(out, n)
		}
	}
	return out
}

// Names joins the names of needs for a message: "ipset, conntrack".
func Names(needs []Need) string {
	names := make([]string, len(needs))
	for i, n := range needs {
		names[i] = n.Name
	}
	return strings.Join(names, ", ")
}

// Ensure provides every need of f that is missing. It never gives up on the
// first problem: the Result says what was installed and what was not, so the
// caller can report all of it at once. Err() is what decides whether the
// feature may be switched on.
func Ensure(ctx context.Context, f Feature) Result { return ensure(ctx, f, needsFor(f)) }

// EnsureRequired is Ensure for the needs the feature cannot work without,
// leaving the optional ones alone. It is for a caller that runs again and again
// -- the capture's session restarts every few seconds while its socket keeps
// failing -- and must not start `opkg update` each time because an optional tool
// could not be installed the first time.
func EnsureRequired(ctx context.Context, f Feature) Result {
	var required []Need
	for _, n := range needsFor(f) {
		if !n.optional() {
			required = append(required, n)
		}
	}
	return ensure(ctx, f, required)
}

func ensure(ctx context.Context, f Feature, needs []Need) Result {
	res := Result{Feature: f}

	var missing []Need
	for _, n := range needs {
		if n.Pkg != "" && !present(n) {
			missing = append(missing, n)
		}
	}
	var installErrs map[string]error
	if len(missing) > 0 {
		installMu.Lock()
		installErrs = installPackages(ctx, missing)
		installMu.Unlock()
	}

	for _, n := range needs {
		switch {
		case n.Pkg != "":
			if !contains(missing, n) {
				continue
			}
			switch {
			case present(n):
				res.Installed = append(res.Installed, n)
			case installErrs[n.Pkg] != nil:
				res.Failed = append(res.Failed, Failure{n, installErrs[n.Pkg]})
			default:
				// opkg said yes, and the command still does not run.
				res.Failed = append(res.Failed, Failure{n, errors.New("пакет поставился, но команда всё равно не запускается")})
			}
		default:
			if n.Present != nil && n.Present() {
				continue
			}
			if err := n.Provide(ctx); err != nil {
				res.Failed = append(res.Failed, Failure{n, err})
			} else if n.Present != nil {
				res.Installed = append(res.Installed, n)
			}
		}
	}
	return res
}

// installPackages installs the missing package needs with one `opkg update` and
// one `opkg install`; when that fails it retries them one at a time (without a
// second update), so a package the feed lacks does not hide the ones it has.
// The returned map has an entry for every package that is still missing.
func installPackages(ctx context.Context, missing []Need) map[string]error {
	errs := map[string]error{}
	pkgs := make([]string, len(missing))
	for i, n := range missing {
		pkgs[i] = n.Pkg
	}
	err := opkgInstall(ctx, pkgs...)
	if err == nil {
		return errs
	}
	if len(missing) == 1 {
		errs[missing[0].Pkg] = err
		return errs
	}
	for _, n := range missing {
		if present(n) {
			continue // landed in the joint run
		}
		if e := opkgInstallNoUpdate(ctx, n.Pkg); e != nil {
			errs[n.Pkg] = e
		}
	}
	return errs
}

func present(n Need) bool { return n.Present != nil && n.Present() }

func contains(needs []Need, n Need) bool {
	for _, m := range needs {
		if m.Name == n.Name {
			return true
		}
	}
	return false
}

// Err is non-nil when a need the feature cannot work without is missing; the
// feature should then not be switched on. The message names every such need,
// what it is for, why it could not be provided and what to do by hand. Needs
// that failed for the same reason (an offline router fails them all alike) are
// one sentence with the reason once and one command to type.
func (r Result) Err() error {
	var groups []*failureGroup
	byReason := map[string]*failureGroup{}
	var causes []error
	for _, f := range r.Failed {
		if f.Need.optional() {
			continue
		}
		causes = append(causes, f.Err)
		key := reason(f.Err)
		g := byReason[key]
		if g == nil {
			g = &failureGroup{reason: key}
			byReason[key] = g
			groups = append(groups, g)
		}
		g.needs = append(g.needs, f.Need)
	}
	if len(groups) == 0 {
		return nil
	}
	sentences := make([]string, len(groups))
	for i, g := range groups {
		sentences[i] = g.sentence()
	}
	return &needError{msg: strings.Join(sentences, "\n"), errs: causes}
}

// failureGroup is the required needs that failed for one reason.
type failureGroup struct {
	reason string
	needs  []Need
}

func (g *failureGroup) sentence() string {
	var names, pkgs, hints []string
	for _, n := range g.needs {
		names = append(names, n.Name)
		if n.Pkg != "" {
			pkgs = append(pkgs, n.Pkg)
		} else if n.Hint != "" {
			hints = append(hints, n.Hint)
		}
	}
	var b strings.Builder
	b.WriteString("не удалось подготовить " + strings.Join(names, ", "))
	if len(g.needs) == 1 {
		b.WriteString(" (" + g.needs[0].Why + ")")
	}
	b.WriteString(": " + g.reason)
	if len(pkgs) > 0 {
		b.WriteString(". Вручную: " + manualInstall(pkgs...))
	}
	for _, h := range hints {
		b.WriteString(". " + h)
	}
	return b.String()
}

// manualInstall is the command to type by hand to get pkgs.
func manualInstall(pkgs ...string) string {
	return "opkg update && opkg install " + strings.Join(pkgs, " ")
}

// needError is the error Err returns: the sentence for the operator, with the
// underlying errors (every required failure) still reachable through errors.Is/As.
type needError struct {
	msg  string
	errs []error
}

func (e *needError) Error() string   { return e.msg }
func (e *needError) Unwrap() []error { return e.errs }

// Lines renders what happened for a person: one line per package installed
// (prefixed with okPrefix), then one per optional need that could not be
// provided (prefixed with warnPrefix) with what is lost without it. The prefix
// is where a terminal and a chat differ ("предупреждение: " vs "⚠️ ").
func (r Result) Lines(okPrefix, warnPrefix string) []string {
	var out []string
	for _, n := range r.Installed {
		out = append(out, okPrefix+"поставил "+n.Name+" — "+n.Why)
	}
	for _, f := range r.Failed {
		if !f.Need.optional() {
			continue
		}
		line := fmt.Sprintf("%s%s не поставился (%s) — %s", warnPrefix, f.Need.Name, reason(f.Err), f.Need.Without)
		if f.Need.Pkg != "" {
			line += "; вручную: " + manualInstall(f.Need.Pkg)
		}
		out = append(out, line)
	}
	return out
}

// reason is err as one sentence for the operator: an opkg failure says what it
// found (no network, no space, ...) and quotes the end of opkg's output; any
// other error is its own text.
func reason(err error) string {
	var oe *opkg.Error
	if errors.As(err, &oe) {
		s := oe.Reason
		if s == "" {
			s = oe.Err.Error()
		}
		if oe.Output != "" {
			s += " [" + oe.Output + "]"
		}
		return s
	}
	return err.Error()
}

// --- the catalogue ----------------------------------------------------------

func catalogue(f Feature) []Need {
	switch f {
	case AdaptiveRouting:
		return []Need{
			iptables(),
			ipset(),
			conntrack("уже открытые соединения не будут сразу перенаправляться, только новые попытки"),
		}
	case L7SNI:
		return []Need{
			iptables(),
			nflogModules(),
			conntrack("после совпадения имени уже открытое соединение не переключится сразу, только новые попытки"),
		}
	}
	return nil
}

func iptables() Need {
	return Need{
		Name: "iptables", Pkg: "iptables", Why: "правила перехвата трафика",
		Present: keenetic.IptablesPresent,
	}
}

func ipset() Need {
	return Need{
		Name: "ipset", Pkg: "ipset", Why: "список адресов для переадресации",
		Present: adaptiveroute.IPSetPresent,
	}
}

func conntrack(without string) Need {
	return Need{
		Name: "conntrack", Pkg: "conntrack", Why: "сброс уже открытых соединений",
		Without: without,
		Present: keenetic.ConntrackPresent,
	}
}

// nflogModules is not an opkg package: the kernel modules the capture's rules
// use ship with the firmware and are only loaded on demand (the Entware feed
// has no package for them). A failure here means this firmware does not have
// them.
func nflogModules() Need {
	return Need{
		Name: "модули ядра NFLOG", Why: "перехват имён сайтов (NFLOG, connbytes, length)",
		Hint:    "Возможно, эта прошивка не поддерживает перехват имён — пришли строку ошибки из `keenetic-xray logs 200`",
		Provide: l7capture.EnsureNFLOGModule,
	}
}
