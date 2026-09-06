package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

func cmdSubscription(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray subscription {set-url|refresh|list|set-primary|set-backup} [args]")
	}
	switch args[0] {
	case "set-url":
		return subscriptionSetURL(args[1:])
	case "refresh":
		return subscriptionRefresh()
	case "list":
		return subscriptionList()
	case "set-primary":
		return subscriptionSetRole(args[1:], true)
	case "set-backup":
		return subscriptionSetRole(args[1:], false)
	default:
		return fmt.Errorf("unknown subscription subcommand %q", args[0])
	}
}

func subscriptionSetURL(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keenetic-xray subscription set-url <url>")
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	cfg.Subscription = &config.Subscription{URL: args[0]}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("subscription URL set; run `keenetic-xray subscription refresh` to fetch it")
	return nil
}

func subscriptionRefresh() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	hasShared := cfg.Subscription != nil && cfg.Subscription.URL != ""
	hasSlots := cfg.PrimarySource != nil || cfg.BackupSource != nil
	if !hasShared && !hasSlots {
		return fmt.Errorf("no subscription URL or slot sources set -- run `keenetic-xray subscription set-url <url>` first")
	}
	ctx := context.Background()

	if hasShared {
		var primaryKey, backupKey string
		if p := cfg.Primary(); p != nil {
			primaryKey = p.Remark
		}
		if b := cfg.Backup(); b != nil {
			backupKey = b.Remark
		}
		result, err := subscription.Refresh(ctx, cfg.Subscription.URL, primaryKey, backupKey)
		if err != nil {
			return fmt.Errorf("refreshing subscription: %w", err)
		}
		for _, w := range subscription.ApplyResult(cfg, result) {
			fmt.Println("warning:", w)
		}
		fmt.Printf("subscription: %d profiles\n", len(result.Profiles))
	}

	// Re-fetch independently-sourced slots too -- a shared-subscription
	// refresh deliberately leaves them alone.
	for _, s := range []struct {
		name    string
		src     *config.SlotSource
		primary bool
	}{
		{"primary", cfg.PrimarySource, true},
		{"backup", cfg.BackupSource, false},
	} {
		if s.src == nil {
			continue
		}
		prof, err := subscription.ResolveSource(ctx, s.src.URL, s.src.Selector)
		if err != nil {
			fmt.Printf("warning: source (%s): %v\n", s.name, err)
			continue
		}
		idx := cfg.UpsertProfile(prof)
		if s.primary {
			cfg.PrimaryIndex = idx
		} else {
			cfg.BackupIndex = idx
		}
		fmt.Printf("source (%s) <- %s\n", s.name, prof.Remark)
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	applyDaemonChange(nil, false)
	return nil
}

func subscriptionList() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if cfg.Subscription != nil {
		fmt.Printf("subscription URL: %s\n", cfg.Subscription.URL)
		if !cfg.Subscription.LastFetchedAt.IsZero() {
			fmt.Printf("last fetched: %s\n", cfg.Subscription.LastFetchedAt.Format(time.RFC3339))
		}
	} else {
		fmt.Println("no subscription URL set")
	}
	return profileList()
}

func subscriptionSetRole(args []string, primary bool) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keenetic-xray subscription set-%s <index>", roleWord(primary))
	}
	idx, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid index %q: %w", args[0], err)
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(cfg.Profiles) {
		return fmt.Errorf("index %d out of range (%d profiles)", idx, len(cfg.Profiles))
	}

	if primary {
		cfg.PrimaryIndex = idx
		if cfg.Subscription != nil {
			cfg.Subscription.PrimaryKey = cfg.Profiles[idx].Remark
		}
	} else {
		cfg.BackupIndex = idx
		if cfg.Subscription != nil {
			cfg.Subscription.BackupKey = cfg.Profiles[idx].Remark
		}
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("%s set to profile %d (%s)\n", roleWord(primary), idx, cfg.Profiles[idx].Remark)
	applyDaemonChange(nil, false)
	return nil
}

func roleWord(primary bool) string {
	if primary {
		return "primary"
	}
	return "backup"
}
