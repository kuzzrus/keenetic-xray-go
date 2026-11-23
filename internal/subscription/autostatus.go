package subscription

import (
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// LastRefresh is when the subscription was last refreshed, by hand or by the
// daemon: the later of Subscription.LastFetchedAt (which only a refresh that
// reached the config stamps) and the periodic refresh's own last success.
// Zero when it never was.
func LastRefresh(cfg *config.Config, st RefreshState) time.Time {
	last := st.LastSuccess
	if cfg.Subscription != nil && cfg.Subscription.LastFetchedAt.After(last) {
		last = cfg.Subscription.LastFetchedAt
	}
	return last
}

// AutoStatus is the one-paragraph answer to "is the subscription kept fresh
// automatically": the interval, when it last happened and when it is next due,
// and -- if it keeps failing -- why. Shared by `subscription auto` and the bot; withLast
// leaves out "last refreshed" for a caller that already says so on the line before.
func AutoStatus(cfg *config.Config, st RefreshState, now time.Time, withLast bool) string {
	interval := cfg.SubscriptionRefreshInterval()
	if interval == 0 {
		return "автообновление подписки: выключено"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "автообновление подписки: каждые %s", HumanDuration(interval))
	if !HasRemote(cfg) {
		b.WriteString(" (подписки по ссылке нет — обновлять нечего)")
		return b.String()
	}
	var fetched time.Time
	if cfg.Subscription != nil {
		fetched = cfg.Subscription.LastFetchedAt
	}
	if last := LastRefresh(cfg, st); withLast && !last.IsZero() && !last.After(now) {
		fmt.Fprintf(&b, ", последнее — %s назад", HumanDuration(now.Sub(last)))
	}
	if wait := st.Due(fetched, now, interval).Sub(now); wait > 0 {
		fmt.Fprintf(&b, ", следующее через %s", HumanDuration(wait))
	} else {
		b.WriteString(", следующее — с минуты на минуту")
	}
	if st.Failures > 0 {
		fmt.Fprintf(&b, "\n⚠️ последняя попытка не удалась (подряд: %d): %s", st.Failures, st.LastError)
	}
	return b.String()
}

// HumanDuration is a short Russian duration: "12 ч", "3 ч 10 мин", "45 мин",
// "меньше минуты".
func HumanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	switch {
	case d < time.Minute:
		return "меньше минуты"
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d%time.Hour == 0:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d ч %d мин", int(d.Hours()), int(d.Minutes())%60)
	}
}
