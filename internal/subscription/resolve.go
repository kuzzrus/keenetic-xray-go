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
	p, _, err := ResolveSourcePinned(ctx, src, selector, "")
	return p, err
}

// ResolveSourcePinned is ResolveSource with a stable anchor. When
// importKey is non-empty and a fetched subscription still contains a
// profile with that Profile.ImportKey, that profile wins -- regardless of
// what the provider did to node order or names. Only if the anchored
// server is genuinely gone does it fall back to selector (old behaviour).
// It also returns the ImportKey of whatever it resolved, so the caller
// can persist it as the slot's new anchor (backfilling configs written
// before the field existed).
func ResolveSourcePinned(ctx context.Context, src, selector, importKey string) (config.Profile, string, error) {
	src = strings.TrimSpace(src)
	switch {
	case strings.HasPrefix(src, "vless://"):
		p, err := config.ParseVLESSURI(src)
		if err != nil {
			return config.Profile{}, "", err
		}
		return p, p.ImportKey(), nil
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		res, err := Refresh(ctx, src, "", "")
		if err != nil {
			return config.Profile{}, "", err
		}
		if importKey != "" {
			for _, p := range res.Profiles {
				if p.ImportKey() == importKey {
					return p, importKey, nil
				}
			}
		}
		p, err := Pick(res.Profiles, selector)
		if err != nil {
			return config.Profile{}, "", err
		}
		return p, p.ImportKey(), nil
	default:
		return config.Profile{}, "", fmt.Errorf("нужна vless:// ссылка или http(s):// URL")
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
