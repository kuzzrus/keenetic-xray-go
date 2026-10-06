package depscan

import (
	"errors"
	"strconv"
	"strings"
)

// The agent answers the bot's routes_scan with this tab-separated form,
// which the bot parses back into a Result to draw its screen -- the same
// split as dns_test_top: structure for the buttons, no string-scraping of
// text meant for people.
//
//	#page  seed  finalHost  status  direct  note  seedIPs  seedIPsDropped
//	#more  more  skipped
//	host   class tier(A|B)  flags  via  covered-by  direct  tunnel  IPs  IPsDropped
//
// flags is a comma list of shared, tracker, unchecked. A Reach is "-"
// (not tried), "ok:<status>" or "err:<reason>".

// TSV renders r in the wire form.
func (r *Result) TSV() string {
	var b strings.Builder
	for _, p := range r.Pages {
		b.WriteString(strings.Join([]string{
			"#page", cell(p.Seed), cell(p.FinalHost), strconv.Itoa(p.Status), encReach(p.Direct), cell(p.Note),
			orDash(strings.Join(p.SeedIPs, ",")), strconv.Itoa(p.SeedIPsDropped),
		}, "\t"))
		b.WriteByte('\n')
	}
	b.WriteString("#more\t" + strconv.Itoa(r.More) + "\t" + strconv.Itoa(r.Skipped) + "\n")
	for _, h := range r.Hosts {
		tier := "A"
		if h.Tier == TierMaybe {
			tier = "B"
		}
		var flags []string
		if h.Shared {
			flags = append(flags, "shared")
		}
		if h.Tracker {
			flags = append(flags, "tracker")
		}
		if h.Unchecked {
			flags = append(flags, "unchecked")
		}
		b.WriteString(strings.Join([]string{
			h.Name, string(h.Class), tier, orDash(strings.Join(flags, ",")),
			orDash(strings.Join(h.Via, ",")), orDash(cell(h.CoveredBy)),
			encReach(h.Direct), encReach(h.Tunnel),
			orDash(strings.Join(h.IPs, ",")), strconv.Itoa(h.IPsDropped),
		}, "\t"))
		b.WriteByte('\n')
	}
	return b.String()
}

// ParseTSV reads TSV's output. Lines it does not understand are skipped
// (a newer agent may add columns or lines); a result with no #page line is
// an error -- that is not scan output at all.
func ParseTSV(s string) (*Result, error) {
	r := &Result{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		switch f[0] {
		case "#page":
			f = pad(f, 8)
			st, _ := strconv.Atoi(f[3])
			dropped, _ := strconv.Atoi(f[7])
			pg := Page{Seed: f[1], FinalHost: f[2], Status: st, Direct: decReach(f[4]), Note: f[5], SeedIPsDropped: dropped}
			if f[6] != "-" && f[6] != "" {
				pg.SeedIPs = strings.Split(f[6], ",")
			}
			r.Pages = append(r.Pages, pg)
		case "#more":
			f = pad(f, 3)
			r.More, _ = strconv.Atoi(f[1])
			r.Skipped, _ = strconv.Atoi(f[2])
		default:
			if strings.HasPrefix(f[0], "#") || len(f) < 8 {
				continue
			}
			h := Host{Name: f[0], Class: Class(f[1]), Direct: decReach(f[6]), Tunnel: decReach(f[7])}
			if _, ok := classOrder[h.Class]; !ok {
				continue
			}
			if f[2] == "B" {
				h.Tier = TierMaybe
			}
			for _, fl := range strings.Split(f[3], ",") {
				switch fl {
				case "shared":
					h.Shared = true
				case "tracker":
					h.Tracker = true
				case "unchecked":
					h.Unchecked = true
				}
			}
			if f[4] != "-" {
				h.Via = strings.Split(f[4], ",")
			}
			if f[5] != "-" {
				h.CoveredBy = f[5]
			}
			if len(f) >= 10 { // older agents end at the tunnel column
				if f[8] != "-" && f[8] != "" {
					h.IPs = strings.Split(f[8], ",")
				}
				h.IPsDropped, _ = strconv.Atoi(f[9])
			}
			r.Hosts = append(r.Hosts, h)
		}
	}
	if len(r.Pages) == 0 {
		return nil, errors.New("depscan: в ответе нет строки #page")
	}
	return r, nil
}

func pad(f []string, n int) []string {
	for len(f) < n {
		f = append(f, "")
	}
	return f
}

// cell makes s safe to put in one TSV field.
func cell(s string) string {
	return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func encReach(r Reach) string {
	switch {
	case !r.Tried:
		return "-"
	case r.OK:
		return "ok:" + strconv.Itoa(r.Status)
	}
	return "err:" + cell(r.Err)
}

func decReach(s string) Reach {
	switch {
	case strings.HasPrefix(s, "ok:"):
		st, _ := strconv.Atoi(s[3:])
		return Reach{Tried: true, OK: true, Status: st}
	case strings.HasPrefix(s, "err:"):
		return Reach{Tried: true, Err: s[4:]}
	}
	return Reach{}
}
