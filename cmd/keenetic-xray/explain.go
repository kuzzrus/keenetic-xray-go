package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// `keenetic-xray explain <имя|ip>` (and the bot's /why) answers the question an
// operator asks most often: "does this site go through the tunnel, and why?".
//
// Three independent mechanisms can send a flow into the tunnel, and until now
// an operator had to read each of them by hand (`routes show`, `show
// running-config`, `transport adaptive list`, the exclusion file):
//
//   - a DNS-routing list -- the router's own (domain-listN) or one of this
//     project's routes -- whose entry covers the name (or, for an address entry,
//     the resolved address) and that is routed into an interface;
//   - the adaptive set, where the classifier or the L7 capture put an address;
//   - and the things that keep an address out of the second: the operator's
//     never-route list and the Russian ranges.
//
// explain reads all of them, for one name or address, and says what it found.
// It changes nothing. The only side effect is the one any client has: resolving
// the name through the router's resolver, which may put its addresses into the
// ipset of a list that covers it.

// explainTimeout bounds one explanation; the slow part is `show running-config`.
const explainTimeout = 30 * time.Second

// explainEnv is everything explain reads from the world, so that a test can
// stand in for each part.
type explainEnv struct {
	cfg *config.Config

	// resolve returns the IPv4 addresses of a name -- the router's own resolver,
	// so the answer is the one its clients get.
	resolve func(ctx context.Context, name string) ([]string, error)

	// cname returns the canonical name behind a name (the end of its CNAME chain).
	// The router follows CNAME chains when it matches a DNS-routing list, so a
	// name whose CDN target is on a list is routed although it is not itself.
	cname func(ctx context.Context, name string) (string, error)

	// routes reads the router's DNS-routing lists; nil when this is not a Keenetic.
	routes func(ctx context.Context) ([]keenetic.LiveRoute, error)

	// members reads the adaptive set (nil: not a router) and notes says how an
	// entry of it got there.
	members func(ctx context.Context) ([]adaptiveroute.Member, error)
	notes   func(addr string) (adaptiveroute.Note, bool)

	// exclusions is the operator's never-route list (nil-safe); ruRange says
	// whether an address is in a Russian range, the classifier's other veto.
	exclusions *adaptiveroute.Exclusions
	ruRange    func(ip string) (cidr string, ok bool)
}

// explainNet is one subnet (or single address) entry of a list.
type explainNet struct {
	text string // as the operator would write it: "149.154.160.0/20", "1.2.3.4"
	net  *net.IPNet
}

// explainList is one list that routes traffic: the router's own, or one of this
// config's. Entries are classified once, here, not per question.
type explainList struct {
	name    string // the object-group, or the config list's name
	group   string // the object-group this list is (or would be) on the router
	ours    bool   // one of this project's lists
	iface   string // where it routes; "" -> nowhere, the list has no effect
	toUs    bool   // iface ends in our own xray (Config.L7SNIEgress)
	reject  bool   // strict: when the interface is down, drop instead of leaking direct
	domains map[string]struct{}
	nets    []explainNet
}

func newExplainList(cfg *config.Config, name, group string, ours bool, iface string, reject bool, entries []string) explainList {
	l := explainList{
		name: name, group: group, ours: ours, iface: iface, reject: reject,
		toUs: cfg.L7SNIEgress(iface), domains: map[string]struct{}{},
	}
	for _, e := range entries {
		kind, canon, err := config.ClassifyRouteEntry(e)
		if err != nil {
			continue
		}
		switch kind {
		case config.RouteDomain:
			l.domains[canon] = struct{}{}
		case config.RouteSubnet:
			cidr := canon
			if !strings.Contains(cidr, "/") { // a single address comes back bare
				cidr += "/32"
			}
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				l.nets = append(l.nets, explainNet{text: canon, net: n})
			}
		}
	}
	return l
}

// coversName reports which entry of the list covers name: the name itself or
// one of its parent domains, on a '.' boundary ("whatsapp.com" covers
// "web.whatsapp.com", not "notwhatsapp.com").
func (l explainList) coversName(name string) (entry string, ok bool) {
	if len(l.domains) == 0 {
		return "", false
	}
	for host := name; ; {
		if _, hit := l.domains[host]; hit {
			return host, true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return "", false
		}
		host = host[i+1:]
	}
}

// coversIP reports which subnet entry of the list covers ip.
func (l explainList) coversIP(ip net.IP) (entry string, ok bool) {
	for _, n := range l.nets {
		if n.net.Contains(ip) {
			return n.text, true
		}
	}
	return "", false
}

// explainListsFromRoutes turns the router's lists into explainLists. A group
// that exists but is not routed anywhere has no effect and is left out.
func explainListsFromRoutes(cfg *config.Config, routes []keenetic.LiveRoute) []explainList {
	var out []explainList
	for _, lr := range routes {
		if lr.Iface == "" {
			continue
		}
		ours := strings.HasPrefix(lr.Group, keenetic.RouteGroupPrefix)
		out = append(out, newExplainList(cfg, lr.Group, lr.Group, ours, lr.Iface, lr.Reject, lr.Entries))
	}
	sortExplainLists(out)
	return out
}

// explainListsFromConfig turns this config's enabled route lists into
// explainLists: what would be on the router once they are applied.
func explainListsFromConfig(cfg *config.Config) []explainList {
	var out []explainList
	for _, rl := range cfg.Routing.Lists {
		if rl.Disabled {
			continue
		}
		group := keenetic.RouteGroupPrefix + config.SanitizeRouteListName(rl.Name)
		out = append(out, newExplainList(cfg, rl.Name, group, true, cfg.L7SNIListIface(rl), rl.Exclusive, rl.Entries))
	}
	sortExplainLists(out)
	return out
}

func sortExplainLists(ls []explainList) {
	sort.SliceStable(ls, func(i, j int) bool { return ls[i].name < ls[j].name })
}

// explainHit is one list that covers the question.
type explainHit struct {
	List   string
	Ours   bool
	Iface  string
	ToUs   bool
	Reject bool
	Entry  string // the domain or subnet of the list that covers it
	Via    string // the CNAME target the entry covers, when it is not the name itself
}

func hitOf(l explainList, entry string) explainHit {
	return explainHit{List: l.name, Ours: l.ours, Iface: l.iface, ToUs: l.toUs, Reject: l.reject, Entry: entry}
}

// firstHits picks, in order, the first hit routed into our own xray and the
// first routed to another interface (either may be nil).
func firstHits(hits []explainHit) (toUs, elsewhere *explainHit) {
	for i := range hits {
		h := &hits[i]
		switch {
		case h.ToUs && toUs == nil:
			toUs = h
		case !h.ToUs && h.Iface != "" && elsewhere == nil:
			elsewhere = h
		}
	}
	return toUs, elsewhere
}

// nameHit reports whether l covers name -- or, the way the router matches, the
// canonical name at the end of its CNAME chain (cname, "" when there is none).
func nameHit(l explainList, name, cname string) (explainHit, bool) {
	if e, ok := l.coversName(name); ok {
		return hitOf(l, e), true
	}
	if cname != "" {
		if e, ok := l.coversName(cname); ok {
			h := hitOf(l, e)
			h.Via = cname
			return h, true
		}
	}
	return explainHit{}, false
}

// explainAddr is everything known about one address.
type explainAddr struct {
	IP       net.IP
	Private  bool                  // a LAN / loopback / multicast address: never routed
	Lists    []explainHit          // subnet entries of lists that cover it
	Adaptive []adaptiveroute.Entry // members of the adaptive set that cover it (the address itself or a widened block)
	Excluded string                // the never-route entry that covers it
	RURange  string                // the Russian range that covers it
}

// explainReport is what was found, before it is put into words.
type explainReport struct {
	Query string
	Name  string // "" when the query was an address

	ResolveErr error
	CNAME      string // the canonical name behind Name, "" when there is none
	Addrs      []explainAddr

	Source    string // where the lists were read from: "роутер" | "конфиг"
	RoutesErr error  // why the router's lists could not be read (Source is "конфиг" then)
	OnRouter  bool

	NameHits   []explainHit // lists whose domain entries cover Name
	NotApplied []string     // config lists that cover the query but have no group on the router

	AdaptiveOn  bool
	AdaptiveErr error // the adaptive set could not be read
	L7On        bool  // L7 SNI is on and has adaptive routing to feed
}

var errNotARouter = errors.New("это не роутер Keenetic")

// parseExplainQuery accepts what an operator pastes: a name, a URL, host:port,
// an IPv4 address. Exactly one of name and ip is set on success.
func parseExplainQuery(q string) (name string, ip net.IP, err error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil, errors.New("укажите имя сайта или IPv4-адрес")
	}
	if strings.Contains(q, "://") {
		u, perr := url.Parse(q)
		if perr != nil || u.Hostname() == "" {
			return "", nil, fmt.Errorf("%q: не удалось разобрать адрес", q)
		}
		q = u.Hostname()
	}
	if _, _, cerr := net.ParseCIDR(q); cerr == nil { // before the path is cut off: "1.2.3.0/24" is not "1.2.3.0"
		return "", nil, fmt.Errorf("%q: нужно имя или один адрес, а не подсеть", q)
	}
	if i := strings.IndexAny(q, "/?#"); i >= 0 { // "example.com/path"
		q = q[:i]
	}
	if host, _, serr := net.SplitHostPort(q); serr == nil { // "example.com:443"
		q = host
	}
	q = strings.TrimSuffix(strings.TrimSpace(q), ".")
	if p := net.ParseIP(q); p != nil {
		if v4 := p.To4(); v4 != nil {
			return "", v4, nil
		}
		return "", nil, fmt.Errorf("%q: IPv6 пока не поддерживается — укажите IPv4-адрес или имя", q)
	}
	kind, canon, cerr := config.ClassifyRouteEntry(q)
	if cerr != nil {
		return "", nil, cerr
	}
	if kind != config.RouteDomain {
		return "", nil, fmt.Errorf("%q: нужно имя или один адрес, а не подсеть", q)
	}
	return canon, nil, nil
}

func isPrivateV4(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}

// memberCovers reports whether an adaptive-set member (a bare address, or a
// widened block as a CIDR) covers ip.
func memberCovers(m adaptiveroute.Member, ip net.IP) bool {
	if strings.Contains(m.Addr, "/") {
		_, n, err := net.ParseCIDR(m.Addr)
		return err == nil && n.Contains(ip)
	}
	return m.Addr == ip.String()
}

// exclusionCovering returns the entry of the never-route list that covers ip.
func exclusionCovering(ex *adaptiveroute.Exclusions, ip net.IP) string {
	for _, e := range ex.Entries() {
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(ip) {
				return e
			}
		} else if e == ip.String() {
			return e
		}
	}
	return ""
}

// buildExplain gathers everything about query. It fails only for a query it
// cannot make sense of; everything the world refuses to say (the router, the
// resolver, the set) ends up in the report instead.
func buildExplain(ctx context.Context, env explainEnv, query string) (*explainReport, error) {
	name, ip, err := parseExplainQuery(query)
	if err != nil {
		return nil, err
	}
	r := &explainReport{
		Query: strings.TrimSpace(query), Name: name,
		OnRouter:   env.routes != nil,
		AdaptiveOn: env.cfg.AdaptiveRoute.Enabled,
		L7On:       l7sniEnabled(env.cfg),
	}

	var ips []net.IP
	if ip != nil {
		ips = []net.IP{ip}
	} else if env.resolve != nil {
		strs, rerr := env.resolve(ctx, name)
		if rerr != nil {
			r.ResolveErr = rerr
		}
		for _, s := range strs {
			if p := net.ParseIP(s); p != nil && p.To4() != nil {
				ips = append(ips, p.To4())
			}
		}
	}
	if name != "" && env.cname != nil {
		if c, cerr := env.cname(ctx, name); cerr == nil {
			if c = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c)), "."); c != "" && c != name {
				r.CNAME = c
			}
		}
	}

	// The lists: the router's own are what actually routes; this config's are the
	// fallback when the router cannot be read (or this is not a router).
	cfgLists := explainListsFromConfig(env.cfg)
	lists := cfgLists
	r.Source = "конфиг"
	routerGroups := map[string]bool{} // every group on the router, routed or not
	if env.routes != nil {
		routes, rerr := env.routes(ctx)
		if rerr != nil {
			r.RoutesErr = rerr
		} else {
			for _, lr := range routes {
				routerGroups[lr.Group] = true
			}
			lists, r.Source = explainListsFromRoutes(env.cfg, routes), "роутер"
		}
	}

	if name != "" {
		for _, l := range lists {
			if h, ok := nameHit(l, name, r.CNAME); ok {
				r.NameHits = append(r.NameHits, h)
			}
		}
	}

	var members []adaptiveroute.Member
	if env.members == nil {
		r.AdaptiveErr = errNotARouter
	} else if m, merr := env.members(ctx); merr != nil {
		r.AdaptiveErr = merr
	} else {
		members = m
	}
	for _, p := range ips {
		a := explainAddr{IP: p, Private: isPrivateV4(p), Excluded: exclusionCovering(env.exclusions, p)}
		if env.ruRange != nil {
			a.RURange, _ = env.ruRange(p.String())
		}
		for _, l := range lists {
			if e, ok := l.coversIP(p); ok {
				a.Lists = append(a.Lists, hitOf(l, e))
			}
		}
		for _, m := range members {
			if memberCovers(m, p) {
				e := adaptiveroute.Entry{Member: m}
				if env.notes != nil {
					e.Note, e.Known = env.notes(m.Addr)
				}
				a.Adaptive = append(a.Adaptive, e)
			}
		}
		r.Addrs = append(r.Addrs, a)
	}

	// A list of this config that covers the question but is not on the router:
	// the commonest reason for "it is in my list, and it does not work".
	if r.Source == "роутер" {
		for _, l := range cfgLists {
			if routerGroups[l.group] { // there; whether it routes is another matter
				continue
			}
			covers := false
			if name != "" {
				_, covers = nameHit(l, name, r.CNAME)
			}
			for _, p := range ips {
				if _, ok := l.coversIP(p); ok {
					covers = true
				}
			}
			if covers {
				r.NotApplied = append(r.NotApplied, l.name)
			}
		}
	}
	return r, nil
}

// explainPath is where a flow to an address ends up.
type explainPath int

const (
	pathDirect    explainPath = iota // straight out the WAN
	pathList                         // through a list routed into our own xray
	pathAdaptive                     // redirected by the adaptive set
	pathElsewhere                    // through another interface (a list the operator pointed there)
)

// pathOf decides where a flow to a goes, and says why. A list routed into our
// xray wins; then the adaptive set (its REDIRECT is the first thing a new
// connection meets); then a list routed elsewhere.
func (r *explainReport) pathOf(a explainAddr) (explainPath, string) {
	toUs, elsewhere := firstHits(append(append([]explainHit(nil), r.NameHits...), a.Lists...))
	var adaptive *adaptiveroute.Entry
	if r.AdaptiveOn && len(a.Adaptive) > 0 {
		adaptive = &a.Adaptive[0]
	}

	switch {
	case a.Private:
		return pathDirect, "напрямую: это адрес локальной сети, через туннель такие не ходят"
	case toUs != nil:
		return pathList, fmt.Sprintf("в туннель по списку «%s» → %s", toUs.List, toUs.Iface)
	case adaptive != nil:
		why := "в туннель: адаптивный набор (" + explainEntryText(*adaptive) + ")"
		if elsewhere != nil {
			why += fmt.Sprintf(" — хотя список «%s» ведёт через %s; адаптивный REDIRECT, скорее всего, перехватит трафик раньше", elsewhere.List, elsewhere.Iface)
		}
		return pathAdaptive, why
	case elsewhere != nil:
		return pathElsewhere, fmt.Sprintf("не в туннель: список «%s» ведёт через %s", elsewhere.List, elsewhere.Iface)
	case a.Excluded != "":
		return pathDirect, fmt.Sprintf("напрямую: адрес в вашем списке исключений (%s), адаптивка его не заворачивает", a.Excluded)
	case a.RURange != "":
		return pathDirect, fmt.Sprintf("напрямую: российский диапазон (%s), адаптивка такие адреса не заворачивает", a.RURange)
	case len(a.Adaptive) > 0:
		return pathDirect, "напрямую: адрес есть в адаптивном наборе, но адаптивная маршрутизация выключена — набор не применяется"
	case !r.AdaptiveOn:
		return pathDirect, "напрямую: ни один список не покрывает, адаптивная маршрутизация выключена"
	}
	return pathDirect, "напрямую: ни один список не покрывает, адаптивка этот адрес не заворачивала"
}

// explainEntryText says how an adaptive-set entry got there, in one line.
func explainEntryText(e adaptiveroute.Entry) string {
	parts := []string{adaptiveroute.TierLabel(e.Tier())}
	if strings.Contains(e.Addr, "/") {
		parts[0] += " " + e.Addr
	}
	if e.HasTimeout {
		parts = append(parts, "осталось "+adaptiveroute.FormatLeft(e.Left))
	} else {
		parts = append(parts, "без срока")
	}
	if e.Known {
		if why := adaptiveroute.ReasonLabel(e.Note.Reason); why != "" {
			parts = append(parts, "причина: "+why)
		}
		if e.Note.Host != "" {
			parts = append(parts, "имя "+e.Note.Host)
		}
		if f := e.Note.Flow(); f != "" {
			parts = append(parts, "клиент "+f)
		}
	}
	return strings.Join(parts, ", ")
}

func hitText(h explainHit) string {
	s := fmt.Sprintf("«%s» → %s", h.List, h.Iface)
	if h.ToUs {
		s += " (в наш xray)"
	} else {
		s += " (не в наш xray)"
	}
	if h.Reject {
		s += ", строгий режим"
	}
	if h.Entry != "" {
		s += ": " + h.Entry
	}
	if h.Via != "" {
		s += " (через CNAME " + h.Via + ")"
	}
	return s
}

// maxExplainAddrs bounds the per-address lines for a name that resolves to many.
const maxExplainAddrs = 8

// renderExplain puts a report into words (Russian, plain text: the CLI prints it
// and the bot sends it as it is).
func renderExplain(r *explainReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔎 %s\n", r.Query)

	if r.Name != "" {
		switch {
		case r.ResolveErr != nil && len(r.Addrs) == 0:
			fmt.Fprintf(&b, "Имя не резолвится: %v\n", r.ResolveErr)
		case len(r.Addrs) > 0:
			ips := make([]string, 0, len(r.Addrs))
			for _, a := range r.Addrs {
				ips = append(ips, a.IP.String())
			}
			how := "DNS роутера"
			if r.CNAME != "" {
				how += "; CNAME: " + r.CNAME
			}
			fmt.Fprintf(&b, "Имя → %s (%s)\n", strings.Join(ips, ", "), how)
		}
	}

	if !r.OnRouter {
		b.WriteString("ℹ️ Это не роутер Keenetic: списки роутера и адаптивный набор недоступны, показаны только списки конфига.\n")
	} else if r.RoutesErr != nil {
		fmt.Fprintf(&b, "⚠️ Списки роутера прочитать не удалось (%v) — показаны списки конфига.\n", r.RoutesErr)
	}

	// Lists that cover the name.
	if r.Name != "" {
		fmt.Fprintf(&b, "\nСписки (%s):\n", r.Source)
		if len(r.NameHits) == 0 {
			b.WriteString("  имя не входит ни в один список\n")
		}
		for _, h := range r.NameHits {
			fmt.Fprintf(&b, "  • %s\n", hitText(h))
		}
		for _, n := range r.NotApplied {
			fmt.Fprintf(&b, "  ⚠️ список «%s» из конфига покрывает имя, но на роутере его группы нет — список не применён\n", n)
		}
	} else if len(r.NotApplied) > 0 {
		for _, n := range r.NotApplied {
			fmt.Fprintf(&b, "⚠️ список «%s» из конфига покрывает адрес, но на роутере его группы нет — список не применён\n", n)
		}
	}

	// Per address.
	shown := r.Addrs
	if len(shown) > maxExplainAddrs {
		shown = shown[:maxExplainAddrs]
	}
	if len(shown) > 0 {
		state := "выключена"
		if r.AdaptiveOn {
			state = "включена"
		}
		fmt.Fprintf(&b, "\nАдреса (адаптивная маршрутизация %s):\n", state)
	}
	for _, a := range shown {
		var facts []string
		for _, h := range a.Lists {
			facts = append(facts, "в списке "+hitText(h))
		}
		for _, e := range a.Adaptive {
			facts = append(facts, "в наборе: "+explainEntryText(e))
		}
		if a.Excluded != "" {
			facts = append(facts, "в списке исключений: "+a.Excluded)
		}
		if a.RURange != "" {
			facts = append(facts, "российский диапазон: "+a.RURange)
		}
		if a.Private {
			facts = append(facts, "адрес локальной сети")
		}
		if len(facts) == 0 {
			facts = []string{"ни списки, ни набор, ни исключения его не затрагивают"}
		}
		fmt.Fprintf(&b, "  %s — %s\n", a.IP, strings.Join(facts, "; "))
	}
	if len(r.Addrs) > len(shown) {
		fmt.Fprintf(&b, "  …и ещё %d\n", len(r.Addrs)-len(shown))
	}
	// Off a router the note at the top already says so; with adaptive routing
	// off the set may simply not exist, which is not worth a warning.
	if r.AdaptiveErr != nil && r.OnRouter && r.AdaptiveOn {
		fmt.Fprintf(&b, "  ⚠️ адаптивный набор прочитать не удалось: %v\n", r.AdaptiveErr)
	}

	// L7: only a name can be caught by name.
	if r.Name != "" {
		// L7 reads the name out of the connection (ClientHello, HTTP Host) and
		// compares that with the lists; it knows nothing of CNAME chains.
		b.WriteString("\nL7 (по имени): ")
		var direct, viaOnly []explainHit
		for _, h := range r.NameHits {
			if h.Via != "" {
				viaOnly = append(viaOnly, h)
			} else {
				direct = append(direct, h)
			}
		}
		toUs, elsewhere := firstHits(direct)
		switch {
		case elsewhere != nil:
			fmt.Fprintf(&b, "не трогает — имя в списке «%s» через %s\n", elsewhere.List, elsewhere.Iface)
		case toUs != nil && r.L7On:
			b.WriteString("если соединение пойдёт мимо DNS-маршрута (DoH, зашитый адрес), увидит имя (ClientHello, HTTP Host) и положит адрес в адаптивный набор\n")
		case toUs != nil:
			b.WriteString("выключен (нужны L7 SNI и адаптивная маршрутизация) — по имени не ловится\n")
		case len(viaOnly) > 0:
			fmt.Fprintf(&b, "самого имени в списках нет (список «%s» покрывает его CNAME %s) — по имени из соединения не ловится\n", viaOnly[0].List, viaOnly[0].Via)
		default:
			b.WriteString("имени нет в списках — не ловится\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(r.verdictText())
	return b.String()
}

// verdictText is the last line (or two): where the flow goes.
func (r *explainReport) verdictText() string {
	if len(r.Addrs) == 0 {
		// Nothing to look at an address for; the lists still say something.
		var toUs, elsewhere *explainHit
		for i := range r.NameHits {
			h := &r.NameHits[i]
			if h.ToUs && toUs == nil {
				toUs = h
			} else if !h.ToUs && h.Iface != "" && elsewhere == nil {
				elsewhere = h
			}
		}
		switch {
		case toUs != nil:
			return fmt.Sprintf("Итог по спискам: имя идёт в туннель — список «%s» → %s (адреса получить не удалось).\n", toUs.List, toUs.Iface)
		case elsewhere != nil:
			return fmt.Sprintf("Итог по спискам: имя идёт не в туннель — список «%s» ведёт через %s (адреса получить не удалось).\n", elsewhere.List, elsewhere.Iface)
		}
		return "Итог: адресов нет и списки имя не покрывают — судить не по чему.\n"
	}

	type group struct {
		path explainPath
		why  string
		n    int
	}
	var groups []group
	for _, a := range r.Addrs {
		p, why := r.pathOf(a)
		found := false
		for i := range groups {
			if groups[i].path == p {
				groups[i].n++
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, group{path: p, why: why, n: 1})
		}
	}

	var b strings.Builder
	if len(groups) == 1 {
		g := groups[0]
		b.WriteString("Итог: " + g.why)
		if g.n > 1 {
			fmt.Fprintf(&b, " (так же и для остальных адресов: всего %d)", g.n)
		}
		b.WriteString(".\n")
	} else {
		var parts []string
		for _, g := range groups {
			word := map[explainPath]string{pathDirect: "напрямую", pathList: "в туннель по списку", pathAdaptive: "в туннель по адаптивному набору", pathElsewhere: "через другой интерфейс"}[g.path]
			parts = append(parts, fmt.Sprintf("%s — %d", word, g.n))
		}
		fmt.Fprintf(&b, "Итог: адреса идут по-разному (%s). Подробности — в строках выше.\n", strings.Join(parts, ", "))
	}

	// Two things worth knowing, said once.
	allDirect, anyList := true, false
	for _, g := range groups {
		if g.path != pathDirect {
			allDirect = false
		}
		if g.path == pathList {
			anyList = true
		}
	}
	nameToUs := false // a list covers the NAME (an address entry needs no DNS)
	for _, h := range r.NameHits {
		if h.ToUs {
			nameToUs = true
		}
	}
	if anyList && nameToUs {
		b.WriteString("ℹ️ DNS-маршрут работает, пока клиент спрашивает имя у DNS роутера; DoH и зашитые адреса он обходит — их ловит L7.\n")
	}
	if allDirect && r.Name != "" {
		excluded := false
		for _, a := range r.Addrs {
			if a.Excluded != "" || a.RURange != "" || a.Private {
				excluded = true
			}
		}
		if !excluded {
			b.WriteString("ℹ️ Сайт не открывается? Адаптивка заворачивает адрес сама, когда видит оборванные соединения; чтобы заворачивать сразу — добавьте имя в список (🗺 Маршруты).\n")
		}
	}
	return b.String()
}

// explainResolve resolves name through the system resolver (on a router, the
// router's own dns-proxy) and returns its IPv4 addresses.
func explainResolve(ctx context.Context, name string) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, name)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil && !seen[v4.String()] {
			seen[v4.String()] = true
			out = append(out, v4.String())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("у имени нет IPv4-адресов")
	}
	sort.Strings(out)
	return out, nil
}

// explainMaxCNAMEHops bounds the chain followed.
const explainMaxCNAMEHops = 8

// followCNAME walks name's CNAME chain to its end with lookup (one hop per
// call: Go's LookupCNAME returns the first target, not the last). The error is
// the first lookup's; a failure further along ends the walk where it stands.
func followCNAME(ctx context.Context, name string, lookup func(context.Context, string) (string, error)) (string, error) {
	cur := name
	for i := 0; i < explainMaxCNAMEHops; i++ {
		next, err := lookup(ctx, cur)
		if err != nil {
			if i == 0 {
				return "", err
			}
			break
		}
		next = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(next)), ".")
		if next == "" || next == cur {
			break
		}
		cur = next
	}
	return cur, nil
}

// explainCNAME is the canonical name at the end of name's CNAME chain, through
// the system resolver.
func explainCNAME(ctx context.Context, name string) (string, error) {
	return followCNAME(ctx, name, func(ctx context.Context, n string) (string, error) {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupCNAME(rctx, n)
	})
}

// explainNow explains query against this machine: the config on disk, the
// router's lists, the live adaptive set. The CLI and the bot's /why both call
// it; in the daemon the in-memory notes of the classifier are used, in the CLI
// the snapshot the daemon published.
func explainNow(ctx context.Context, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, explainTimeout)
	defer cancel()
	cfg, err := config.Load(configPath())
	if err != nil {
		return "", fmt.Errorf("config: %w", err)
	}
	ex, _ := adaptiveroute.LoadExclusions(adaptiveroute.ExclusionsPath(configPath()))
	snap, _ := adaptiveroute.ReadSnapshot(adaptiveRouteSnapshotPath())
	if georanges.CurrentLen() == 0 { // the CLI is not the daemon: load the table here
		georangesLoadLocal(func(string, ...any) {})
	}
	env := explainEnv{
		cfg:        cfg,
		resolve:    explainResolve,
		cname:      explainCNAME,
		exclusions: ex,
		ruRange:    georanges.Lookup,
		notes: func(addr string) (adaptiveroute.Note, bool) {
			if n, ok := adaptiveroute.LookupNote(addr); ok {
				return n, true
			}
			if snap != nil {
				return snap.Lookup(addr)
			}
			return adaptiveroute.Note{}, false
		},
	}
	if keenetic.Available() {
		env.routes = keenetic.AllRoutes
		env.members = func(ctx context.Context) ([]adaptiveroute.Member, error) {
			return adaptiveroute.MembersDetailed(ctx, adaptiveRouteIPSet)
		}
	}
	rep, err := buildExplain(ctx, env, query)
	if err != nil {
		return "", err
	}
	return renderExplain(rep), nil
}

// cmdExplain is `keenetic-xray explain <имя|ip>`.
func cmdExplain(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: keenetic-xray explain <имя|ip>   — идёт ли сайт через туннель и почему")
	}
	out, err := explainNow(context.Background(), args[0])
	if err != nil {
		return err
	}
	_, _ = fmt.Fprint(os.Stdout, out)
	return nil
}
