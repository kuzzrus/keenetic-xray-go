package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

// cmdSetup is the interactive first-run configuration menu -- the local
// SSH-driven counterpart to the remote bot: run this command directly on
// the router to pick a primary/backup pair from either a pasted vless://
// link or a subscription URL.
func cmdSetup(args []string) error {
	return runSetup(os.Stdin)
}

func runSetup(stdin io.Reader) error {
	reader := bufio.NewReader(stdin)
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	fmt.Println("keenetic-xray setup")
	fmt.Println("Paste a vless:// link, or a subscription http(s):// URL:")
	fmt.Print("> ")
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading input: %w", err)
	}
	input := strings.TrimSpace(line)
	if input == "" {
		return fmt.Errorf("no input given")
	}

	var profiles []config.Profile
	switch {
	case strings.HasPrefix(input, "vless://"):
		p, err := config.ParseVLESSURI(input)
		if err != nil {
			return fmt.Errorf("parsing vless link: %w", err)
		}
		profiles = []config.Profile{p}
	case strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://"):
		fmt.Println("fetching subscription...")
		result, err := subscription.Refresh(context.Background(), input, "", "")
		if err != nil {
			return fmt.Errorf("fetching subscription: %w", err)
		}
		for _, w := range result.Warnings {
			fmt.Println("warning:", w)
		}
		profiles = result.Profiles
		cfg.Subscription = &config.Subscription{URL: input, LastFetchedAt: time.Now()}
	default:
		return fmt.Errorf("input doesn't look like a vless:// link or an http(s):// subscription URL")
	}

	if len(profiles) == 0 {
		return fmt.Errorf("no usable vless:// profiles found")
	}
	cfg.Profiles = profiles

	fmt.Println("\nAvailable profiles:")
	for i, p := range profiles {
		fmt.Printf("  %d: %s -- %s:%d\n", i, p.Remark, p.Address, p.Port)
	}

	primaryIdx, err := promptIndex(reader, "Select PRIMARY", len(profiles), 0)
	if err != nil {
		return err
	}
	backupIdx := primaryIdx
	if len(profiles) > 1 {
		defaultBackup := 1
		if primaryIdx == 1 {
			defaultBackup = 0
		}
		backupIdx, err = promptIndex(reader, "Select BACKUP", len(profiles), defaultBackup)
		if err != nil {
			return err
		}
	}

	cfg.PrimaryIndex = primaryIdx
	cfg.BackupIndex = backupIdx
	if cfg.Subscription != nil {
		cfg.Subscription.PrimaryKey = profiles[primaryIdx].Remark
		cfg.Subscription.BackupKey = profiles[backupIdx].Remark
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}

	fmt.Printf("\nSaved: primary=%s, backup=%s\n", profiles[primaryIdx].Remark, profiles[backupIdx].Remark)
	fmt.Println("Start the failover daemon with: keenetic-xray daemon")
	return nil
}

// promptIndex reads a line, re-prompting on invalid input; an empty line
// (just Enter) accepts def.
func promptIndex(reader *bufio.Reader, label string, count, def int) (int, error) {
	for {
		fmt.Printf("%s [0-%d, default %d]: ", label, count-1, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return 0, fmt.Errorf("reading input: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 0 || idx >= count {
			fmt.Println("invalid selection, try again")
			continue
		}
		return idx, nil
	}
}
