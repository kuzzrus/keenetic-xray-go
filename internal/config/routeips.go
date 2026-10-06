package config

import (
	"fmt"
	"sort"
	"strings"
)

// CompanionIPs is what AddCompanionIPs did.
type CompanionIPs struct {
	List     string   // the companion list's name
	Created  bool     // it did not exist before
	Added    []string // entries newly added, normalized
	Rejected []string // entries not added, each with the reason
	Total    int      // entries in the companion now
}

// AddCompanionIPs puts IPv4 addresses into the IP companion of the route
// list base -- "<base>-ip", the same pairing the ready-made lists use
// ("youtube" + "youtube-ip") -- creating it if needed.
//
// Why a companion and not the list itself: an address is routed whatever
// name it was reached by, so it often has to leave through a different
// interface than the domains do. Calls are the case that matters: an app
// that sets up a call connects to a media server's address it was handed
// and never asks DNS for it, so a domain entry cannot catch it, and the
// traffic is UDP, which a SOCKS-based Proxy0 may not carry while a
// WireGuard or TUN interface does. As its own list, the companion can be
// bound to that interface on its own (routes set <base>-ip --iface=...).
//
// A new companion starts out like its base -- interface, exclusive,
// disabled -- the same way a preset's companion does.
//
// Only addresses and subnets are accepted; a domain, a private or
// reserved range, or anything over MaxRouteEntriesPerList comes back in
// Rejected. If nothing could be added to a companion made just now, it is
// not left behind empty.
func (c *Config) AddCompanionIPs(base string, ips []string) (CompanionIPs, error) {
	var res CompanionIPs
	bi := c.routeListIndex(base)
	if bi < 0 {
		return res, fmt.Errorf("нет списка %q", strings.TrimSpace(base))
	}
	b := c.Routing.Lists[bi]
	name, err := c.companionName(b.Name)
	if err != nil {
		return res, err
	}
	li := c.routeListIndex(name)
	if li < 0 {
		c.Routing.Lists = append(c.Routing.Lists, RouteList{
			Name: name, Interface: b.Interface, Exclusive: b.Exclusive, Disabled: b.Disabled,
		})
		li = len(c.Routing.Lists) - 1
		res.Created = true
	}
	l := &c.Routing.Lists[li]
	res.List = l.Name

	have := make(map[string]struct{}, len(l.Entries))
	for _, e := range l.Entries {
		have[strings.ToLower(e)] = struct{}{}
	}
	for _, raw := range ips {
		kind, norm, err := ClassifyRouteEntry(raw)
		switch {
		case err != nil:
			res.Rejected = append(res.Rejected, err.Error())
			continue
		case kind != RouteSubnet:
			res.Rejected = append(res.Rejected, fmt.Sprintf("%q: это домен, а не IP-адрес", raw))
			continue
		}
		if _, dup := have[strings.ToLower(norm)]; dup {
			continue
		}
		if len(l.Entries) >= MaxRouteEntriesPerList {
			res.Rejected = append(res.Rejected, fmt.Sprintf("%s: в списке уже %d записей — предел", norm, MaxRouteEntriesPerList))
			continue
		}
		have[strings.ToLower(norm)] = struct{}{}
		l.Entries = append(l.Entries, norm)
		res.Added = append(res.Added, norm)
	}
	sort.Strings(l.Entries)
	res.Total = len(l.Entries)
	if res.Created && len(l.Entries) == 0 {
		c.Routing.Lists = c.Routing.Lists[:len(c.Routing.Lists)-1]
		res.Created = false
		res.Total = 0
		res.List = "" // there is no companion: callers say so rather than name one
	}
	return res, nil
}

func (c *Config) routeListIndex(name string) int {
	name = strings.TrimSpace(name)
	for i := range c.Routing.Lists {
		if strings.EqualFold(c.Routing.Lists[i].Name, name) {
			return i
		}
	}
	return -1
}

// companionName picks the name for base's IP companion: "<base>-ip", or
// "<base>-ips" when that one is a preset's. A name is refused when it is
// too long, when the router-side group name -- cut to 24 characters --
// would come out the same as base's or any other list's (two lists on one
// group), or when it is a preset-bound list, which the next preset sync
// would rewrite and drop what was added here.
func (c *Config) companionName(base string) (string, error) {
	baseSan := SanitizeRouteListName(base)
	for _, suffix := range []string{"-ip", "-ips"} {
		name := base + suffix
		if !ValidRouteListName(name) {
			continue
		}
		san := SanitizeRouteListName(name)
		if san == baseSan {
			continue // the 24-character cut ate the suffix
		}
		clash, existing := false, -1
		for i, l := range c.Routing.Lists {
			if strings.EqualFold(l.Name, name) {
				existing = i
				continue
			}
			if SanitizeRouteListName(l.Name) == san {
				clash = true
			}
		}
		if clash || (existing >= 0 && c.Routing.Lists[existing].Preset != "") {
			continue
		}
		return name, nil
	}
	return "", fmt.Errorf("для списка %q не подобрать имя IP-списка (слишком длинное, занято или принадлежит пресету) — переименуй список короче", base)
}
