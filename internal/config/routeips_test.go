package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func cfgWithLists(lists ...RouteList) *Config {
	c := Default()
	c.Routing.Lists = lists
	return c
}

func (c *Config) listNamed(name string) *RouteList {
	if i := c.routeListIndex(name); i >= 0 {
		return &c.Routing.Lists[i]
	}
	return nil
}

func TestAddCompanionIPs_CreatesLikeItsBase(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls", Entries: []string{"example.com"}, Interface: "OpkgTun0", Exclusive: true})
	res, err := c.AddCompanionIPs("Calls", []string{"95.47.173.35", "95.47.173.36", "95.47.173.35", "1.2.3.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if res.List != "calls-ip" || !res.Created || res.Total != 3 || len(res.Added) != 3 {
		t.Errorf("res = %+v", res)
	}
	l := c.listNamed("calls-ip")
	if l == nil || l.Interface != "OpkgTun0" || !l.Exclusive || l.Preset != "" {
		t.Errorf("companion = %+v, want the base's interface and exclusive, hand-made", l)
	}
	if !slices.Equal(l.Entries, []string{"1.2.3.0/24", "95.47.173.35", "95.47.173.36"}) {
		t.Errorf("entries = %v", l.Entries)
	}
	if base := c.listNamed("calls"); !slices.Equal(base.Entries, []string{"example.com"}) {
		t.Errorf("the base list changed: %v", base.Entries)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the result does not validate: %v", err)
	}

	// A second call reuses it and adds only what is new.
	res, err = c.AddCompanionIPs("calls", []string{"95.47.173.36", "8.8.4.4"})
	if err != nil || res.Created || len(res.Added) != 1 || res.Total != 4 {
		t.Errorf("second add: %+v, %v", res, err)
	}
}

func TestAddCompanionIPs_DisabledBaseMakesADisabledCompanion(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls", Disabled: true})
	if _, err := c.AddCompanionIPs("calls", []string{"8.8.4.4"}); err != nil {
		t.Fatal(err)
	}
	if l := c.listNamed("calls-ip"); l == nil || !l.Disabled {
		t.Errorf("companion = %+v: adding IPs must not switch routing on behind the user's back", l)
	}
}

func TestAddCompanionIPs_RejectsWhatIsNotAPublicAddress(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls"})
	res, err := c.AddCompanionIPs("calls", []string{"youtube.com", "192.168.1.5", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::1", "8.8.4.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0] != "8.8.4.4" || len(res.Rejected) != 5 {
		t.Errorf("added %v rejected %v", res.Added, res.Rejected)
	}
	if !strings.Contains(strings.Join(res.Rejected, "|"), "это домен") {
		t.Errorf("a domain should be named as such: %v", res.Rejected)
	}
}

func TestAddCompanionIPs_NothingAddedLeavesNoEmptyList(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls"})
	res, err := c.AddCompanionIPs("calls", []string{"192.168.1.5", "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.Total != 0 || c.listNamed("calls-ip") != nil || len(c.Routing.Lists) != 1 {
		t.Errorf("an empty companion was left behind: %+v %+v", res, c.Routing.Lists)
	}
	if len(res.Rejected) != 2 {
		t.Errorf("rejected = %v", res.Rejected)
	}
}

func TestAddCompanionIPs_PresetCompanionIsNotTouched(t *testing.T) {
	// "telegram-ip" belongs to the preset: the next sync would rewrite it
	// and drop what the scan added, so the entries go to "telegram-ips".
	c := cfgWithLists(
		RouteList{Name: "telegram", Preset: "telegram"},
		RouteList{Name: "telegram-ip", Preset: "telegram-ip", Entries: []string{"91.108.4.0/22"}},
	)
	res, err := c.AddCompanionIPs("telegram", []string{"8.8.4.4"})
	if err != nil {
		t.Fatal(err)
	}
	if res.List != "telegram-ips" {
		t.Errorf("went to %q", res.List)
	}
	if pre := c.listNamed("telegram-ip"); !slices.Equal(pre.Entries, []string{"91.108.4.0/22"}) {
		t.Errorf("the preset's companion changed: %v", pre.Entries)
	}
	// Both taken by presets: refuse, say why.
	c.Routing.Lists = append(c.Routing.Lists, RouteList{Name: "telegram-ips", Preset: "x"})
	if _, err := c.AddCompanionIPs("telegram", []string{"8.8.4.4"}); err == nil || !strings.Contains(err.Error(), "пресет") {
		t.Errorf("err = %v", err)
	}
}

func TestAddCompanionIPs_NamesTheRouterCannotTell(t *testing.T) {
	// Group names are cut to 24 characters: for a 24-character base the
	// suffix would vanish and both lists would land on one router group.
	long := strings.Repeat("a", 24)
	c := cfgWithLists(RouteList{Name: long})
	if _, err := c.AddCompanionIPs(long, []string{"8.8.4.4"}); err == nil {
		t.Error("a companion whose router name equals its base's was created")
	}
	if len(c.Routing.Lists) != 1 {
		t.Errorf("lists = %+v", c.Routing.Lists)
	}
	// Past 32 characters the name is simply invalid.
	over := strings.Repeat("b", 31)
	c = cfgWithLists(RouteList{Name: over})
	if _, err := c.AddCompanionIPs(over, []string{"8.8.4.4"}); err == nil {
		t.Error("a 34-character companion name was accepted")
	}
	// Another list that already owns the sanitized name blocks it too.
	c = cfgWithLists(RouteList{Name: "calls"}, RouteList{Name: "calls_ip"}) // sanitizes to "calls-ip"
	if res, err := c.AddCompanionIPs("calls", []string{"8.8.4.4"}); err != nil || res.List != "calls-ips" {
		t.Errorf("res=%+v err=%v, want a fall back to calls-ips", res, err)
	}
}

func TestAddCompanionIPs_UnknownBase(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls"})
	if _, err := c.AddCompanionIPs("nope", []string{"8.8.4.4"}); err == nil || !strings.Contains(err.Error(), "нет списка") {
		t.Errorf("err = %v", err)
	}
}

func TestAddCompanionIPs_StopsAtTheListLimit(t *testing.T) {
	var entries []string
	for i := 0; i < MaxRouteEntriesPerList-1; i++ {
		entries = append(entries, fmt.Sprintf("8.%d.%d.1", i/200+1, i%200+1))
	}
	c := cfgWithLists(RouteList{Name: "calls"}, RouteList{Name: "calls-ip", Entries: entries})
	res, err := c.AddCompanionIPs("calls", []string{"9.9.9.1", "9.9.9.2", "9.9.9.3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || len(res.Rejected) != 2 || res.Total != MaxRouteEntriesPerList {
		t.Errorf("res = %+v", res)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("over the limit: %v", err)
	}
}

func TestAddCompanionIPs_NoCompanionNoName(t *testing.T) {
	c := cfgWithLists(RouteList{Name: "calls"})
	res, err := c.AddCompanionIPs("calls", []string{"example.org"})
	if err != nil || res.List != "" {
		t.Errorf("res=%+v err=%v: a companion that was not left behind must not be named", res, err)
	}
}
