package subscription

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// ResolveSource turns one failover slot's source -- a raw vless:// link
// or an http(s):// subscription URL (with an optional selector) -- into a
// single Profile. Shared by the bot's 🔗 Источники flow and by a refresh
// that re-fetches independently-sourced slots.
func ResolveSource(ctx context.Context, src, selector string) (config.Profile, error) {
	src = strings.TrimSpace(src)
	switch {
	case strings.HasPrefix(src, "vless://"):
		return config.ParseVLESSURI(src)
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		res, err := Refresh(ctx, src, "", "")
		if err != nil {
			return config.Profile{}, err
		}
		return Pick(res.Profiles, selector)
	default:
		return config.Profile{}, fmt.Errorf("нужна vless:// ссылка или http(s):// URL")
	}
}

// Pick selects one profile from a subscription's list by selector:
// "" / "first" -> [0]; an integer -> that index; otherwise a unique
// case-insensitive Remark substring.
func Pick(ps []config.Profile, selector string) (config.Profile, error) {
	if len(ps) == 0 {
		return config.Profile{}, fmt.Errorf("в подписке нет профилей")
	}
	if selector == "" || strings.EqualFold(selector, "first") {
		return ps[0], nil
	}
	if n, err := strconv.Atoi(selector); err == nil {
		if n < 0 || n >= len(ps) {
			return config.Profile{}, fmt.Errorf("индекс %d вне диапазона (%d профилей)", n, len(ps))
		}
		return ps[n], nil
	}
	match, matches := config.Profile{}, 0
	for _, p := range ps {
		if strings.Contains(strings.ToLower(p.Remark), strings.ToLower(selector)) {
			match, matches = p, matches+1
		}
	}
	switch matches {
	case 1:
		return match, nil
	case 0:
		return config.Profile{}, fmt.Errorf("нет профиля с %q в названии", selector)
	default:
		return config.Profile{}, fmt.Errorf("под %q подходит %d профилей — уточни селектор", selector, matches)
	}
}
