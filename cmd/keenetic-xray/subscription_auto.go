package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

const (
	// subRefreshSettle lets the daemon (and the network, and the tunnel a
	// blocked provider is reached through) come up before the first fetch.
	subRefreshSettle = 90 * time.Second
	// subRefreshPoll is the longest the loop sleeps: it looks at the config
	// again at least this often, so `subscription auto off|6` and the bot's
	// /sub_auto take effect without anything having to wake the loop.
	subRefreshPoll = 10 * time.Minute
	// subRefreshShrinkMin: below this many profiles a shrinking list is not
	// suspicious (a provider with two nodes dropping one is just a change).
	subRefreshShrinkMin = 4
)

// errConfigMoved: the config on disk changed, in what a refresh reads or
// writes, while the subscription was being fetched.
var errConfigMoved = errors.New("config changed during the refresh")

// shrunkError: the fresh list is less than half of the one it would replace.
// An unattended refresh does not apply that -- a provider that hiccups, or
// answers an expired subscription with a placeholder node, would otherwise
// replace a working pool with it. The operator's own 🔄 Обновить подписку does.
type shrunkError struct{ before, after int }

func (e *shrunkError) Error() string {
	return fmt.Sprintf("подписка вернула %d профилей вместо %d", e.after, e.before)
}

// autoRefresher is the daemon's periodic subscription refresh. Its effects are
// fields so tests can drive tick without a daemon, a clock or a bot.
type autoRefresher struct {
	logf      func(string, ...any)
	events    chan<- botcontrol.Event // nil when there is no bot
	reload    func() bool             // makes the running daemon adopt config.json
	now       func() time.Time
	statePath string
}

// subscriptionAutoRefreshLoop refreshes the subscription (and any
// independently-sourced slot) every config.SubscriptionRefreshInterval -- twelve
// hours unless set otherwise, off with `subscription auto off`. Best-effort: a
// failed fetch is retried on a back-off (subscription.RetryDelay) and, if it
// keeps failing for a whole interval, reported once to the bot.
func subscriptionAutoRefreshLoop(ctx context.Context, logf func(string, ...any), events chan<- botcontrol.Event) {
	r := &autoRefresher{
		logf: logf, events: events, reload: signalDaemonReload,
		now: time.Now, statePath: subscriptionRefreshStatePath(),
	}
	timer := time.NewTimer(subRefreshSettle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(r.tick(ctx))
	}
}

// tick looks at the config and, if a refresh is due, does it. It returns how
// long to sleep before the next look.
func (r *autoRefresher) tick(ctx context.Context) time.Duration {
	cfg, err := config.Load(configPath())
	if err != nil {
		r.logf("subscription: автообновление: не прочитать конфиг: %v", err)
		return subRefreshPoll
	}
	interval := cfg.SubscriptionRefreshInterval()
	if interval == 0 || !subscription.HasRemote(cfg) {
		return subRefreshPoll
	}
	st := subscription.LoadRefreshState(r.statePath)
	var fetched time.Time
	if cfg.Subscription != nil {
		fetched = cfg.Subscription.LastFetchedAt
	}
	now := r.now()
	if wait := st.Due(fetched, now, interval).Sub(now); wait > 0 {
		return min(wait, subRefreshPoll)
	}
	if wait := r.refresh(ctx, cfg, st, interval); wait > 0 {
		return wait
	}
	// Done (or failed and recorded): the next look decides from the new state.
	// Never shorter than the poll, so an attempt cannot be retried in a spin.
	return subRefreshPoll
}

// refresh makes one attempt and records it. A non-zero result is how long to
// wait instead of following the schedule (the config moved under the attempt).
func (r *autoRefresher) refresh(ctx context.Context, cfg *config.Config, st subscription.RefreshState, interval time.Duration) time.Duration {
	start := r.now()
	res, err := r.attempt(ctx, cfg)
	var shrunk *shrunkError
	switch {
	case errors.Is(err, errConfigMoved):
		r.logf("subscription: конфиг изменился во время обновления — повторю через минуту")
		return time.Minute
	case err != nil:
		msg := subscription.RedactURLs(err.Error())
		st.NoteFailure(start, msg)
		r.logf("subscription: автообновление не удалось (попыток подряд: %d): %s", st.Failures, msg)
		switch {
		case errors.As(err, &shrunk) && !st.FailNotified:
			st.FailNotified = true
			r.push("⚠️ Автообновление подписки пропущено: " + msg +
				".\nПохоже на сбой у провайдера — я не стал подменять рабочий список. Если так и должно быть: 🔄 Обновить подписку (или /sub_refresh) применит как есть.")
		case st.FailureOverdue(start, interval):
			st.FailNotified = true
			r.push(fmt.Sprintf("⚠️ Подписка не обновляется уже %s: %s", subscription.HumanDuration(start.Sub(st.FailingSince)), msg))
		}
	default:
		st.NoteSuccess(start)
		r.logf("subscription: автообновление: %d профилей%s", res.Count, changedWord(res.Changed))
		if res.Changed {
			// The daemon runs on what it loaded, so it has to be told; only when
			// something it uses moved, because adopting a config restarts xray.
			if !r.reload() {
				r.logf("subscription: демон не получил сигнал перечитать конфиг — применится при следующем рестарте")
			}
		}
		if len(res.Lines) > 0 {
			r.push(strings.Join(res.Lines, "\n"))
		}
		// A note about a slot is said once per wording, not every twelve hours.
		if len(res.Notes) == 0 {
			st.WarnHash = ""
		} else if h := fingerprint(res.Notes); h != st.WarnHash {
			st.WarnHash = h
			r.push("⚠️ Подписка: " + strings.Join(res.Notes, "\n⚠️ "))
		}
	}
	if err := subscription.SaveRefreshState(r.statePath, st); err != nil {
		r.logf("subscription: не записать состояние автообновления: %v", err)
	}
	return 0
}

// push sends one message to the bot, if there is one; never blocks the loop.
func (r *autoRefresher) push(text string) {
	if r.events == nil {
		return
	}
	select {
	case r.events <- botcontrol.Event{Kind: "sub_refresh", Text: text, Time: r.now()}:
	default:
		r.logf("subscription: очередь событий бота занята — сообщение пропущено")
	}
}

// autoResult is what a successful attempt did.
type autoResult struct {
	Count   int      // profiles in the config now
	Changed bool     // what the daemon runs on differs from before: it must reload
	Lines   []string // the operator-facing summary of the change; empty when nothing is worth saying
	Notes   []string // slot notes and slot-source errors
}

// attempt fetches, then applies and saves, without ever holding stale config:
// the fetches take as long as the provider takes, and the operator (the bot,
// the CLI) may change the config meanwhile -- so the refreshed fields are
// transplanted into a config read just before saving, and only if what the
// refresh read and wrote has not moved since cfg was loaded.
func (r *autoRefresher) attempt(ctx context.Context, cfg *config.Config) (autoResult, error) {
	before := takeView(cfg)
	inputs := refreshInputs(cfg)

	rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rep, err := subscription.RefreshConfig(rctx, cfg)
	if err != nil {
		return autoResult{}, err
	}
	var notes []string
	notes = append(notes, rep.SlotNotes...)
	failedSources := 0
	for _, s := range rep.Sources {
		if s.Err != nil {
			failedSources++
			notes = append(notes, fmt.Sprintf("источник (%s): %s", slotRu(s.Slot), subscription.RedactURLs(s.Err.Error())))
		}
	}
	if !rep.Shared && failedSources > 0 && failedSources == len(rep.Sources) {
		return autoResult{}, errors.New(notes[len(notes)-1])
	}

	after := takeView(cfg)
	if before.n >= subRefreshShrinkMin && after.n*2 < before.n {
		return autoResult{}, &shrunkError{before: before.n, after: after.n}
	}

	latest, err := config.Load(configPath())
	if err != nil {
		return autoResult{}, err
	}
	if !bytes.Equal(inputs, refreshInputs(latest)) {
		return autoResult{}, errConfigMoved
	}
	adoptRefresh(latest, cfg)
	if err := latest.Save(configPath()); err != nil {
		return autoResult{}, err
	}
	return autoResult{
		Count:   after.n,
		Changed: needsReload(before, after),
		Lines:   describeChange(before, after),
		Notes:   notes,
	}, nil
}

// refreshInputs is everything RefreshConfig reads or writes, serialized: two
// equal results mean nothing the refresh depends on moved in between.
func refreshInputs(cfg *config.Config) []byte {
	b, _ := json.Marshal(struct {
		Subscription  *config.Subscription
		PrimarySource *config.SlotSource
		BackupSource  *config.SlotSource
		Profiles      []config.Profile
		Primary       int
		Backup        int
	}{cfg.Subscription, cfg.PrimarySource, cfg.BackupSource, cfg.Profiles, cfg.PrimaryIndex, cfg.BackupIndex})
	return b
}

// adoptRefresh copies the fields RefreshConfig owns from src into dst, a config
// read just now: whatever else the operator changed in the meantime stays.
func adoptRefresh(dst, src *config.Config) {
	dst.Profiles = src.Profiles
	dst.PrimaryIndex, dst.BackupIndex = src.PrimaryIndex, src.BackupIndex
	dst.Subscription = src.Subscription
	dst.PrimarySource, dst.BackupSource = src.PrimarySource, src.BackupSource
}

// refreshView is what a refresh is judged by. A server is its connection
// fingerprint (Profile.ImportKey), not its name: panels put counters in names
// ("📊 осталось 112 ГБ") that change on every fetch, and that is no reason to
// restart xray or to write to the operator.
type refreshView struct {
	n       int               // profiles, for the shrink guard and the message
	servers map[string]server // by connection fingerprint
	pool    string            // every server's connection and settings, blind to names and order
	primary slotView
	backup  slotView
}

type server struct{ remark, content string } // content: every field but the name

type slotView struct{ key, remark, content string } // key is "" for an empty slot

func fingerprint(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// contentOf fingerprints a profile without its name.
func contentOf(p config.Profile) string {
	p.Remark = ""
	return fingerprint(p)
}

func takeView(cfg *config.Config) refreshView {
	v := refreshView{n: len(cfg.Profiles), servers: make(map[string]server, len(cfg.Profiles))}
	parts := make([]string, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		key, content := p.ImportKey(), contentOf(p)
		if _, dup := v.servers[key]; dup { // two entries on one endpoint stay two entries
			key += "#" + content[:6]
		}
		v.servers[key] = server{p.Remark, content}
		parts = append(parts, key+":"+content)
	}
	sort.Strings(parts)
	v.pool = fingerprint(parts)
	slot := func(p *config.Profile) slotView {
		if p == nil {
			return slotView{}
		}
		return slotView{p.ImportKey(), p.Remark, contentOf(*p)}
	}
	v.primary, v.backup = slot(cfg.Primary()), slot(cfg.Backup())
	return v
}

// needsReload reports whether the daemon, which runs on what it loaded, must
// adopt the refreshed config: the servers it can use changed, or the ones in its
// two slots did. A renamed or reordered list changes only names and indexes --
// the daemon's own copy stays self-consistent without it, and adopting a config
// restarts xray.
func needsReload(before, after refreshView) bool {
	return before.pool != after.pool || before.primary.content != after.primary.content || before.backup.content != after.backup.content
}

// describeChange is the message for the operator, or nil when nothing happened
// that is worth one (a rename, a reorder).
func describeChange(before, after refreshView) []string {
	var added, removed, changed []string
	for key, s := range after.servers {
		switch old, ok := before.servers[key]; {
		case !ok:
			added = append(added, s.remark)
		case old.content != s.content:
			changed = append(changed, s.remark)
		}
	}
	for key, s := range before.servers {
		if _, ok := after.servers[key]; !ok {
			removed = append(removed, s.remark)
		}
	}
	// A server that moved (a new address behind the same name) is one change, not
	// one removal and one addition.
	gone := make(map[string]bool, len(removed))
	for _, n := range removed {
		gone[n] = true
	}
	var fresh []string
	for _, n := range added {
		if gone[n] {
			delete(gone, n)
			changed = append(changed, n)
		} else {
			fresh = append(fresh, n)
		}
	}
	added, removed = fresh, removed[:0]
	for n := range gone {
		removed = append(removed, n)
	}
	var lines []string
	if len(added) > 0 {
		lines = append(lines, "  + "+nameList(added))
	}
	if len(removed) > 0 {
		lines = append(lines, "  − "+nameList(removed))
	}
	if len(changed) > 0 {
		lines = append(lines, "  ~ параметры изменились: "+nameList(changed))
	}
	for _, s := range []struct {
		word     string
		was, now slotView
	}{
		{"основной", before.primary, after.primary},
		{"резервный", before.backup, after.backup},
	} {
		switch {
		case s.was.key != s.now.key && s.was.remark == s.now.remark:
			lines = append(lines, fmt.Sprintf("  %s (%s): сменился адрес или транспорт", s.word, s.now.remark))
		case s.was.key != s.now.key:
			lines = append(lines, fmt.Sprintf("  %s: %s → %s", s.word, orNone(s.was.remark), orNone(s.now.remark)))
		case s.was.content != s.now.content:
			lines = append(lines, fmt.Sprintf("  %s (%s): параметры сервера изменились", s.word, s.now.remark))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{fmt.Sprintf("🔄 Подписка обновлена автоматически: %d профилей", after.n)}, lines...)
}

// nameList is a sorted, shortened list of names for a chat message.
func nameList(names []string) string {
	sort.Strings(names)
	const show = 5
	if len(names) <= show {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s и ещё %d", strings.Join(names[:show], ", "), len(names)-show)
}

func orNone(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func slotRu(slot string) string {
	if slot == "backup" {
		return "резервный"
	}
	return "основной"
}

func changedWord(changed bool) string {
	if changed {
		return ", есть изменения"
	}
	return ", без изменений"
}
