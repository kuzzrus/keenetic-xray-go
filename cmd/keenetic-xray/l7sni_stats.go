package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// What the L7 capture saw and did, counted. The point of the QUIC "observe"
// mode is to look before acting -- how many Initials arrive, how many
// decrypt, how many ClientHellos carry an Encrypted Client Hello extension,
// which names show up -- and these counters (and the short list of names
// behind them) are what it looks with. They live in the daemon's memory and
// are published to a small file for `transport l7sni stats` and the bot, the
// same way adaptive routing publishes its snapshot.
//
// The keys are the JSON keys of the published file as well; keep them stable.
const (
	statTLSHello = "tls_hello" // TLS ClientHellos parsed on TCP/443
	statTLSName  = "tls_name"  // ... that carried a usable server_name
	statTLSECH   = "tls_ech"   // ... that carried an encrypted_client_hello extension
	statTLSMatch = "tls_match" // ... whose name matched a routes list
	statTLSActed = "tls_acted" // ... and was redirected

	statHTTPHost  = "http_host"  // Host headers read on TCP/80
	statHTTPMatch = "http_match" // ... that matched a routes list
	statHTTPActed = "http_acted" // ... and were redirected

	statQUICDatagram   = "quic_datagram"    // UDP/443 datagrams handed to the QUIC parser
	statQUICNotInitial = "quic_not_initial" // ... that were not a v1/v2 client Initial
	statQUICBadVersion = "quic_bad_version" // ... long headers of a version we cannot decrypt
	statQUICMalformed  = "quic_malformed"   // ... whose header or frames did not parse
	statQUICAuthFailed = "quic_auth_failed" // ... that looked like an Initial but failed the AEAD tag
	statQUICInitial    = "quic_initial"     // Initial packets decrypted
	statQUICWaiting    = "quic_waiting"     // ... that began or continued a ClientHello that goes on in a later datagram
	statQUICHello      = "quic_hello"       // whole ClientHellos assembled
	statQUICName       = "quic_name"        // ... that carried a usable server_name
	statQUICECH        = "quic_ech"         // ... that carried an encrypted_client_hello extension
	statQUICMatch      = "quic_match"       // ... whose name matched a routes list (counted in observe mode too)
	statQUICActed      = "quic_acted"       // ... and were redirected (act mode)
)

// l7sniNameTable bounds the list of names kept for the "most seen" view.
const l7sniNameTable = 512

type l7sniNameStat struct {
	proto, host string
	n, ech      uint64
}

// l7sniStats is safe for concurrent use: the capture goroutine records, the
// publisher goroutine reads.
type l7sniStats struct {
	mu        sync.Mutex
	since     time.Time
	counts    map[string]uint64
	names     map[string]*l7sniNameStat // key: proto + " " + host
	reads     uint64                    // NFLOG recv() calls that carried packets
	messages  uint64                    // packets those calls carried
	dirty     bool
	lastWrite time.Time
}

func newL7SNIStats(now time.Time) *l7sniStats {
	return &l7sniStats{since: now, counts: map[string]uint64{}, names: map[string]*l7sniNameStat{}}
}

func (s *l7sniStats) inc(key string) {
	s.mu.Lock()
	s.counts[key]++
	s.dirty = true
	s.mu.Unlock()
}

// seenName records one sighting of a name for the "most seen" view. When the
// table is full the least-seen entry makes room, so a long tail of one-off
// names (rr1---sn-....googlevideo.com) cannot push the busy ones out.
func (s *l7sniStats) seenName(proto, host string, ech bool) {
	if host == "" {
		return
	}
	key := proto + " " + host
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.names[key]
	if e == nil {
		if len(s.names) >= l7sniNameTable {
			var victim string
			var least uint64 = ^uint64(0)
			for k, v := range s.names {
				if v.n < least {
					victim, least = k, v.n
				}
			}
			delete(s.names, victim)
		}
		e = &l7sniNameStat{proto: proto, host: host}
		s.names[key] = e
	}
	e.n++
	if ech {
		e.ech++
	}
	s.dirty = true
}

// setBatches stores the NFLOG read counters (cumulative, from the capture).
func (s *l7sniStats) setBatches(reads, messages uint64) {
	s.mu.Lock()
	if reads != s.reads || messages != s.messages {
		s.reads, s.messages = reads, messages
		s.dirty = true
	}
	s.mu.Unlock()
}

// l7sniStatsVersion is bumped when the published layout changes; a file of
// another version reads as missing, like the adaptive snapshot.
const l7sniStatsVersion = 1

// l7sniStatsFile is what is published.
type l7sniStatsFile struct {
	Version  int               `json:"v"`
	Since    time.Time         `json:"since"`
	At       time.Time         `json:"at"`
	QUIC     string            `json:"quic"` // the mode the capture is running with
	Counts   map[string]uint64 `json:"counts"`
	Reads    uint64            `json:"nflog_reads"`
	Messages uint64            `json:"nflog_messages"`
	Top      []l7sniTopName    `json:"top"`
}

type l7sniTopName struct {
	Proto string `json:"proto"`
	Host  string `json:"host"`
	N     uint64 `json:"n"`
	ECH   uint64 `json:"ech"`
}

// l7sniTopCount is how many names the published file carries.
const l7sniTopCount = 15

func (s *l7sniStats) snapshot(now time.Time, quicMode string) l7sniStatsFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := l7sniStatsFile{
		Version: l7sniStatsVersion, Since: s.since, At: now, QUIC: quicMode,
		Counts: make(map[string]uint64, len(s.counts)), Reads: s.reads, Messages: s.messages,
	}
	for k, v := range s.counts {
		f.Counts[k] = v
	}
	for _, e := range s.names {
		f.Top = append(f.Top, l7sniTopName{Proto: e.proto, Host: e.host, N: e.n, ECH: e.ech})
	}
	sort.Slice(f.Top, func(i, j int) bool {
		if f.Top[i].N != f.Top[j].N {
			return f.Top[i].N > f.Top[j].N
		}
		return f.Top[i].Proto+f.Top[i].Host < f.Top[j].Proto+f.Top[j].Host
	})
	if len(f.Top) > l7sniTopCount {
		f.Top = f.Top[:l7sniTopCount]
	}
	return f
}

// publishIfDirty writes the snapshot when something changed since the last
// write and at least minInterval has passed; it reports whether it wrote.
// Cheap to call every few seconds.
func (s *l7sniStats) publishIfDirty(path string, now time.Time, minInterval time.Duration, quicMode string) (bool, error) {
	s.mu.Lock()
	due := s.dirty && (s.lastWrite.IsZero() || now.Sub(s.lastWrite) >= minInterval)
	if due {
		s.dirty = false
		s.lastWrite = now
	}
	s.mu.Unlock()
	if !due {
		return false, nil
	}
	if err := writeL7SNIStats(path, s.snapshot(now, quicMode)); err != nil {
		s.mu.Lock()
		s.dirty = true // try again next time
		s.mu.Unlock()
		return false, err
	}
	return true, nil
}

// writeL7SNIStats publishes atomically (temp file, then rename). Mode 0600:
// the file lists names that LAN clients connected to.
func writeL7SNIStats(path string, f l7sniStatsFile) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".l7sni-stats-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// readL7SNIStats loads what the daemon published. A file of another layout
// version reads as missing.
func readL7SNIStats(path string) (*l7sniStatsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f l7sniStatsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Version != l7sniStatsVersion {
		return nil, os.ErrNotExist
	}
	return &f, nil
}

// renderL7SNIStats prints the stats in Russian, the way the other CLI
// summaries read. now is the clock the ages are taken against.
func renderL7SNIStats(w io.Writer, f *l7sniStatsFile, now time.Time) {
	c := f.Counts
	fmt.Fprintf(w, "l7sni: считается с %s (%s назад), файл обновлён %s назад\n",
		f.Since.Local().Format("02.01 15:04"), shortAge(now.Sub(f.Since)), shortAge(now.Sub(f.At)))

	fmt.Fprintf(w, "TLS (TCP/443): ClientHello разобрано %d, с именем %d, с ECH-расширением %d; совпало со списками %d, переправлено %d\n",
		c[statTLSHello], c[statTLSName], c[statTLSECH], c[statTLSMatch], c[statTLSActed])
	fmt.Fprintf(w, "HTTP (TCP/80): Host прочитан %d; совпало со списками %d, переправлено %d\n",
		c[statHTTPHost], c[statHTTPMatch], c[statHTTPActed])

	switch f.QUIC {
	case "observe":
		fmt.Fprintln(w, "QUIC (UDP/443): режим «наблюдение» — считаем, ничего не переправляем")
	case "act":
		fmt.Fprintln(w, "QUIC (UDP/443): режим «действие» — совпавшие имена переправляются")
	default:
		fmt.Fprintln(w, "QUIC (UDP/443): выкл")
	}
	if f.QUIC == "observe" || f.QUIC == "act" || c[statQUICDatagram] > 0 {
		fmt.Fprintf(w, "  датаграмм разобрано %d: Initial расшифровано %d; не Initial %d, версия не поддержана %d, повреждено %d, не сошёлся тег %d\n",
			c[statQUICDatagram], c[statQUICInitial], c[statQUICNotInitial], c[statQUICBadVersion], c[statQUICMalformed], c[statQUICAuthFailed])
		fmt.Fprintf(w, "  ClientHello собрано %d (ждали продолжения в следующей датаграмме %d раз), с именем %d, с ECH-расширением %d\n",
			c[statQUICHello], c[statQUICWaiting], c[statQUICName], c[statQUICECH])
		fmt.Fprintf(w, "  совпало со списками %d, переправлено %d\n", c[statQUICMatch], c[statQUICActed])
		if c[statQUICName] > 0 {
			fmt.Fprintf(w, "  доля ClientHello с ECH-расширением: %s (браузеры шлют его и «для вида» — GREASE, так что это верхняя оценка скрытых имён)\n",
				percent(c[statQUICECH], c[statQUICHello]))
		}
	}

	if f.Reads > 0 {
		fmt.Fprintf(w, "NFLOG: %d пакетов за %d чтений, в среднем %.2f пакета на чтение (около 1 — ядро отдаёт каждый пакет сразу)\n",
			f.Messages, f.Reads, float64(f.Messages)/float64(f.Reads))
	}

	if len(f.Top) > 0 {
		fmt.Fprintln(w, "Чаще всего видны имена:")
		for _, t := range f.Top {
			ech := ""
			if t.ECH > 0 {
				ech = fmt.Sprintf(" (ECH в %d)", t.ECH)
			}
			fmt.Fprintf(w, "  %-5s %-48s %d%s\n", strings.ToUpper(t.Proto), t.Host, t.N, ech)
		}
	}
}

func percent(part, whole uint64) string {
	if whole == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(whole))
}

// shortAge renders a duration the way the adaptive-routing summaries do:
// seconds, minutes or hours, no fractions.
func shortAge(d time.Duration) string {
	switch {
	case d < 0:
		return "0 с"
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1f ч", d.Hours())
	}
}
