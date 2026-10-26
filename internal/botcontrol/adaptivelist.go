package botcontrol

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// The router's half of the bot's "что перенаправлено" and "исключения"
// screens: what is in the redirect set and why, and the operator's
// never-route list. The router answers in a small tab-separated text (the
// "#" lines are headers, every other line one row) and the control server
// parses it (telegram_adaptive.go) -- the same shape routes_names uses for
// the 📍 Маршруты screen.

// adaptiveListMaxRows caps how many entries one adrt_list answer carries; the
// header still counts the whole set.
const adaptiveListMaxRows = 200

// adaptiveExclusionSweepTimeout bounds taking an excluded entry out of the
// redirect set (ipset, plus a conntrack delete per connection).
const adaptiveExclusionSweepTimeout = 30 * time.Second

// tsvField makes s safe as one field of a tab-separated line.
func tsvField(s string) string {
	return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
}

// formatAdaptiveList renders the router's answer to adrt_list.
//
//	#n   total  probation confirmed block l7sni unknown
//	#hour/#day/#total   one count per adaptiveroute.Event, in its order
//	#since  unix time of the first event the daemon recorded, 0 if none
//	#excl   how many entries the never-route list holds
//	addr  tier  seconds-left(-1: never expires)  reason  client  proto  dport  host
func formatAdaptiveList(entries []adaptiveroute.Entry, st adaptiveroute.StatsSnapshot, excluded int) string {
	var b strings.Builder
	t := adaptiveroute.TallyEntries(entries)
	fmt.Fprintf(&b, "#n\t%d\t%d\t%d\t%d\t%d\t%d\n", t.Total, t.Probation, t.Confirmed, t.Block, t.L7SNI, t.Unknown)
	for _, w := range []struct {
		name string
		c    adaptiveroute.Counts
	}{{"hour", st.Hour}, {"day", st.Day}, {"total", st.Total}} {
		b.WriteString("#" + w.name)
		for _, n := range w.c {
			fmt.Fprintf(&b, "\t%d", n)
		}
		b.WriteByte('\n')
	}
	since := int64(0)
	if !st.Since.IsZero() {
		since = st.Since.Unix()
	}
	fmt.Fprintf(&b, "#since\t%d\n#excl\t%d\n", since, excluded)

	for i, e := range entries {
		if i >= adaptiveListMaxRows {
			break
		}
		left := -1
		if e.HasTimeout {
			left = int(e.Left / time.Second)
		}
		n := e.Note
		if !e.Known {
			n = adaptiveroute.Note{}
		}
		fmt.Fprintf(&b, "%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\n",
			tsvField(e.Addr), tsvField(e.Tier()), left, tsvField(n.Reason), tsvField(n.Client), tsvField(n.Proto), n.DPort, tsvField(n.Host))
	}
	return b.String()
}

// excludedPath is where this router's never-route list lives.
func (h *RouterHandler) excludedPath() (string, error) {
	if h.ConfigPath == "" {
		return "", fmt.Errorf("путь к конфигу не задан — список исключений некуда писать")
	}
	return adaptiveroute.ExclusionsPath(h.ConfigPath), nil
}

// adaptiveRouteList answers adrt_list. The daemon's own memory is what knows
// why each address is in the set, and this handler runs in the daemon, so it
// reads the notes directly (a CLI in another process reads the published
// snapshot instead).
func (h *RouterHandler) adaptiveRouteList(ctx context.Context) (string, error) {
	if !h.Config.AdaptiveRoute.Enabled {
		return "", fmt.Errorf("адаптивная маршрутизация выключена — перенаправлять нечего")
	}
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}
	entries, err := adaptiveroute.ListEntries(ctx, adaptiveroute.RedirectSetName)
	if err != nil {
		return "", fmt.Errorf("чтение ipset: %w", err)
	}
	excluded := 0
	if path, perr := h.excludedPath(); perr == nil {
		if ex, lerr := adaptiveroute.LoadExclusions(path); lerr == nil {
			excluded = ex.Len()
		}
	}
	return formatAdaptiveList(entries, adaptiveroute.Stats(time.Now()), excluded), nil
}

// adaptiveRouteExclude answers adrt_excl: put args[0] on the never-route
// list and take whatever it covers out of the redirect set right now, so the
// answer on screen is already true. The classify loop sees the list change
// within a tick and drops the same entries from the classifier's memory; the
// l7sni capture reads the list too.
func (h *RouterHandler) adaptiveRouteExclude(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: adrt_excl <ip|a.b.c.d/nn>")
	}
	path, err := h.excludedPath()
	if err != nil {
		return "", err
	}
	canon, added, err := adaptiveroute.AddExclusion(path, args[0])
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if added {
		fmt.Fprintf(&b, "🚫 Исключено: %s", canon)
	} else {
		fmt.Fprintf(&b, "%s уже в списке исключений", canon)
	}
	if keenetic.Available() {
		if ex, lerr := adaptiveroute.LoadExclusions(path); lerr == nil {
			sctx, cancel := context.WithTimeout(ctx, adaptiveExclusionSweepTimeout)
			removed, serr := adaptiveroute.SweepExcluded(sctx, adaptiveroute.RedirectSetName, ex, keenetic.DeleteConntrackToward)
			cancel()
			if len(removed) > 0 {
				fmt.Fprintf(&b, "\nУбрано из перенаправления: %s. Открытые соединения оборваны — переподключатся напрямую.", strings.Join(removed, ", "))
			}
			if serr != nil {
				fmt.Fprintf(&b, "\n⚠️ не всё удалось убрать из ipset: %v", serr)
			}
		}
	}
	return b.String(), nil
}

// adaptiveRouteInclude answers adrt_incl: take args[0] back off the list.
// Nothing becomes redirected by it; the classifier merely may catch the
// address again if it looks blocked.
func (h *RouterHandler) adaptiveRouteInclude(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: adrt_incl <ip|a.b.c.d/nn>")
	}
	path, err := h.excludedPath()
	if err != nil {
		return "", err
	}
	canon, removed, err := adaptiveroute.RemoveExclusion(path, args[0])
	if err != nil {
		return "", err
	}
	if !removed {
		return canon + " не было в списке исключений", nil
	}
	return fmt.Sprintf("↩️ Возвращено: %s. Классификатор снова может его ловить, если он выглядит заблокированным.", canon), nil
}

// adaptiveRouteExcluded answers adrt_exlist: a "#excl <count> <skipped>"
// header, then one entry per line.
func (h *RouterHandler) adaptiveRouteExcluded() (string, error) {
	path, err := h.excludedPath()
	if err != nil {
		return "", err
	}
	ex, err := adaptiveroute.LoadExclusions(path)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#excl\t%d\t%d\n", ex.Len(), ex.Skipped)
	for _, e := range ex.Entries() {
		b.WriteString(e + "\n")
	}
	return b.String(), nil
}

// adaptiveActivityText is the block the adaptive-routing status adds about
// what the classifier has been doing: where the redirected entries stand,
// and what became of the probations. Every line starts with a newline.
func adaptiveActivityText(t adaptiveroute.Tally, st adaptiveroute.StatsSnapshot, excluded int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nСейчас перенаправлено: %d", t.Total)
	if t.Total > 0 {
		fmt.Fprintf(&b, " — на пробе %d · подтверждено %d · подсетей %d", t.Probation, t.Confirmed, t.Block)
		if t.L7SNI > 0 {
			fmt.Fprintf(&b, " · по имени %d", t.L7SNI)
		}
		if t.Unknown > 0 {
			fmt.Fprintf(&b, " · без пометки %d", t.Unknown)
		}
	}
	if st.Since.IsZero() {
		b.WriteString("\nС запуска демона классификатор ничего не ловил")
	} else {
		fmt.Fprintf(&b, "\nЗа час: %s", st.Hour.SummaryRU())
		fmt.Fprintf(&b, "\nЗа сутки: %s", st.Day.SummaryRU())
		fmt.Fprintf(&b, "\n(счётчики с %s, обнуляются при перезапуске демона)", st.Since.Local().Format("02.01 15:04"))
	}
	if excluded > 0 {
		fmt.Fprintf(&b, "\nИсключений (не перенаправляются никогда): %d", excluded)
	}
	return b.String()
}

// atoiOr is strconv.Atoi with a fallback, for parsing the tab-separated
// answers above without ceremony.
func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
