package adaptiveroute

import (
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
)

// The words the bot and the CLI use for tiers and reasons. One place, so
// the two never describe the same event differently.

// TierLabel names a tier.
func TierLabel(tier string) string {
	switch tier {
	case TierProbation:
		return "проба"
	case TierConfirmed:
		return "подтверждён"
	case TierBlock:
		return "подсеть"
	case TierL7SNI:
		return "по имени"
	}
	return "без пометки"
}

// TierIcon is the one-glyph marker lists put in front of an entry.
func TierIcon(tier string) string {
	switch tier {
	case TierProbation:
		return "🧪"
	case TierConfirmed:
		return "✅"
	case TierBlock:
		return "🌐"
	case TierL7SNI:
		return "🔍"
	}
	return "❔"
}

// ReasonLabel says in words what tripped an entry.
func ReasonLabel(reason string) string {
	switch reason {
	case classifier.ReasonSilentSYN:
		return "SYN ушёл, ответа нет"
	case classifier.ReasonClosedNoReply:
		return "соединение закрылось без ответа"
	case classifier.ReasonQUICNoReply:
		return "QUIC без ответа"
	case classifier.ReasonTCPStall:
		return "TCP завис: данные ушли, ответа нет"
	case classifier.ReasonLateStall:
		return "ответы пропали посреди соединения"
	case classifier.ReasonJudgedGood:
		return "через туннель заработало"
	case classifier.ReasonJudgedFailed:
		return "туннель не помог"
	case classifier.ReasonOKFailed:
		return "перестал работать через туннель"
	case classifier.ReasonOKRefresh:
		return "подтверждён повторно"
	case classifier.ReasonBlockWiden:
		return "укрупнение: несколько подтверждённых адресов в одной сети"
	case classifier.ReasonExcluded:
		return "исключён вручную"
	case ReasonRestored:
		return "восстановлен после перезапуска демона"
	case ReasonL7SNI:
		return "имя совпало со списком маршрутов"
	case "":
		return "причина неизвестна"
	}
	return reason
}

// FormatLeft renders a time-to-live compactly: "42с", "17м", "5ч 54м".
func FormatLeft(d time.Duration) string {
	switch {
	case d < 0:
		d = 0
		fallthrough
	case d < time.Minute:
		return fmt.Sprintf("%dс", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dм", int(d/time.Minute))
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	if m == 0 {
		return fmt.Sprintf("%dч", h)
	}
	return fmt.Sprintf("%dч %dм", h, m)
}

// Flow describes the connection that tripped an entry: "192.168.1.50 tcp/443",
// "" when nothing is known.
func (n Note) Flow() string {
	if n.Client == "" {
		return ""
	}
	if n.Proto == "" || n.DPort == 0 {
		return n.Client
	}
	return fmt.Sprintf("%s %s/%d", n.Client, n.Proto, n.DPort)
}

// SummaryRU renders the counts the way the bot status and the CLI show them:
// what became of the probations, then the rarer events when there were any.
func (c Counts) SummaryRU() string {
	parts := []string{
		fmt.Sprintf("проб %d", c.Of(EventProbation)),
		fmt.Sprintf("подтверждено %d", c.Of(EventConfirmed)),
		fmt.Sprintf("истекло без вердикта %d", c.Of(EventLapsed)),
		fmt.Sprintf("не помогло %d", c.Of(EventFailed)),
	}
	if n := c.Of(EventBlock); n > 0 {
		parts = append(parts, fmt.Sprintf("подсетей %d", n))
	}
	if n := c.Of(EventExcluded); n > 0 {
		parts = append(parts, fmt.Sprintf("исключено %d", n))
	}
	return strings.Join(parts, " · ")
}

// Quiet reports whether nothing at all was counted.
func (c Counts) Quiet() bool {
	for _, n := range c {
		if n != 0 {
			return false
		}
	}
	return true
}
