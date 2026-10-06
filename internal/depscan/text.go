package depscan

import (
	"fmt"
	"strings"
)

// ViaLabel is a source in words, for a person.
func ViaLabel(via string) string {
	switch via {
	case ViaRedirect:
		return "редирект"
	case ViaHint:
		return "подсказка браузеру"
	case ViaHTML:
		return "страница"
	case ViaCSP:
		return "политика CSP"
	case ViaScript:
		return "скрипт"
	case ViaForm:
		return "форма"
	}
	return via
}

// Describe is one host's evidence in a line: where it was found and how it
// opened.
func (h Host) Describe() string {
	var parts []string
	if len(h.Via) > 0 {
		labels := make([]string, len(h.Via))
		for i, v := range h.Via {
			labels[i] = ViaLabel(v)
		}
		parts = append(parts, strings.Join(labels, ", "))
	}
	if h.CoveredBy != "" {
		parts = append(parts, "в списке "+h.CoveredBy)
	}
	if h.Direct.Tried {
		parts = append(parts, "напрямую: "+h.Direct.words())
	}
	if h.Tunnel.Tried {
		parts = append(parts, "туннель: "+h.Tunnel.words())
	}
	if h.Unchecked {
		parts = append(parts, "не успел проверить")
	}
	var marks []string
	if h.Shared {
		marks = append(marks, "общий сервис")
	}
	if h.Tracker {
		marks = append(marks, "аналитика/реклама")
	}
	line := strings.Join(parts, "; ")
	if len(marks) > 0 {
		line += " [" + strings.Join(marks, ", ") + "]"
	}
	return line
}

func (r Reach) words() string {
	switch {
	case !r.Tried:
		return "—"
	case r.OK:
		return fmt.Sprintf("отвечает (%d)", r.Status)
	}
	return r.Err
}

// Text renders the whole result for a terminal.
func (r *Result) Text() string {
	var b strings.Builder
	for _, p := range r.Pages {
		fmt.Fprintf(&b, "🔎 %s", p.Seed)
		if p.FinalHost != "" && p.FinalHost != p.Seed {
			fmt.Fprintf(&b, " → %s", p.FinalHost)
		}
		fmt.Fprintf(&b, ": страница открылась через туннель (код %d)", p.Status)
		if p.Direct.OK {
			b.WriteString("; напрямую тоже открывается")
		}
		b.WriteByte('\n')
		if p.Note != "" {
			fmt.Fprintf(&b, "   ⚠️ %s\n", p.Note)
		}
	}
	groups := []struct {
		class Class
		head  string
	}{
		{ClassNeed, "Нужны — напрямую не открываются, через туннель открываются"},
		{ClassMaybe, "Возможно нужны"},
		{ClassDirect, "Открываются и напрямую — в список не нужны"},
		{ClassDead, "Не открылись ни так, ни так"},
		{ClassCovered, "Уже в ваших списках"},
	}
	for _, g := range groups {
		var hs []Host
		for _, h := range r.Hosts {
			if h.Class == g.class {
				hs = append(hs, h)
			}
		}
		if len(hs) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", g.head, len(hs))
		for _, h := range hs {
			fmt.Fprintf(&b, "  %s — %s\n", h.Name, h.Describe())
		}
	}
	if r.More > 0 {
		fmt.Fprintf(&b, "\nЕщё %d хостов не проверял (лимит на одно сканирование).\n", r.More)
	}
	if r.Skipped > 0 {
		fmt.Fprintf(&b, "Пропущено имён, которые нельзя добавить (IP, внутренние, не-ASCII): %d.\n", r.Skipped)
	}
	return strings.TrimRight(b.String(), "\n")
}

// NeedNames returns the hosts the scan recommends adding -- ClassNeed, in
// the order of the result.
func (r *Result) NeedNames() []string {
	var out []string
	for _, h := range r.Hosts {
		if h.Class == ClassNeed {
			out = append(out, h.Name)
		}
	}
	return out
}
