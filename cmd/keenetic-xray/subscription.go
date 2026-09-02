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
	if cfg.Subscription == nil || cfg.Subscription.URL == "" {
		return fmt.Errorf("no subscription URL set -- run `keenetic-xray subscription set-url <url>` first")
	}

	var primaryKey, backupKey string
	if p := cfg.Primary(); p != nil {
		primaryKey = p.Remark
	}
	if b := cfg.Backup(); b != nil {
		backupKey = b.Remark
	}

	result, err := subscription.Refresh(context.Background(), cfg.Subscription.URL, primaryKey, backupKey)
	if err != nil {
		return fmt.Errorf("refreshing subscription: %w", err)
	}

	warnings := subscription.ApplyResult(cfg, result)
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("refreshed: %d profiles\n", len(cfg.Profiles))
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
	return nil
}

func roleWord(primary bool) string {
	if primary {
		return "primary"
	}
	return "backup"
}
