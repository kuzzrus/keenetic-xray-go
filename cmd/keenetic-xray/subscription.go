package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

func cmdSubscription(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray subscription {set-url|refresh|list|set-primary|set-backup|auto} [args]")
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
	case "auto":
		return subscriptionAuto(args[1:])
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
	rep, err := subscription.RefreshConfig(context.Background(), cfg)
	if errors.Is(err, subscription.ErrNothingToRefresh) {
		return fmt.Errorf("no subscription URL or slot sources set -- run `keenetic-xray subscription set-url <url>` first")
	}
	if err != nil {
		return fmt.Errorf("refreshing subscription: %w", err)
	}
	for _, w := range rep.Warnings {
		fmt.Println("warning:", w)
	}
	if rep.Shared {
		fmt.Printf("subscription: %d profiles\n", rep.Profiles)
	}
	for _, s := range rep.Sources {
		if s.Err != nil {
			fmt.Printf("warning: source (%s): %v\n", s.Slot, s.Err)
			continue
		}
		fmt.Printf("source (%s) <- %s\n", s.Slot, s.Remark)
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	applyDaemonChange(nil, false)
	return nil
}

// subscriptionAuto is `subscription auto [status|off|on|<hours>]`: show or set
// how the daemon keeps the subscription fresh by itself. Nothing to signal: the
// daemon's loop reads the config again at least every ten minutes.
func subscriptionAuto(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: keenetic-xray subscription auto [status|off|on|<hours 1..%d>]", config.MaxSubscriptionRefreshHours)
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] != "status" {
		if err := cfg.SetSubscriptionAutoRefresh(args[0]); err != nil {
			return err
		}
		if err := cfg.Save(configPath()); err != nil {
			return err
		}
		fmt.Println("сохранено; демон подхватит это в течение 10 минут")
	}
	fmt.Println(subscription.AutoStatus(cfg, subscription.LoadRefreshState(subscriptionRefreshStatePath()), time.Now(), true))
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
