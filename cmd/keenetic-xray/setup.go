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
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

// setupOpts drives runSetup. With From set (and/or --yes) it runs fully
// non-interactive -- that's the path the .ipk postinst takes when the
// installer was given a link, so `install.sh --sub=...` needs no follow-up
// commands.
type setupOpts struct {
	From       string // vless:// link or http(s):// subscription URL
	PrimarySel string // index or a remark substring; "" -> 0
	BackupSel  string // index or a remark substring; "" -> 1 (or 0 with one profile)
	Proxy0     string // "", "yes", "no" ("" -> prompt interactively, or auto when non-interactive)
	Yes        bool
}

// cmdSetup is the first-run configurator: pick a primary/backup pair from
// a pasted vless:// link or a subscription URL, optionally wire Keenetic's
// Proxy0 to the local inbound, and (interactively) offer to restart the
// daemon so the change takes effect.
func cmdSetup(args []string) error {
	var o setupOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-y":
			o.Yes = true
		case a == "--proxy0":
			o.Proxy0 = "yes"
		case a == "--no-proxy0":
			o.Proxy0 = "no"
		case strings.HasPrefix(a, "--from="):
			o.From = a[len("--from="):]
		case a == "--from" && i+1 < len(args):
			i++
			o.From = args[i]
		case strings.HasPrefix(a, "--primary="):
			o.PrimarySel = a[len("--primary="):]
		case strings.HasPrefix(a, "--backup="):
			o.BackupSel = a[len("--backup="):]
		default:
			return fmt.Errorf("setup: unexpected argument %q", a)
		}
	}
	return runSetup(os.Stdin, o)
}

func runSetup(stdin io.Reader, o setupOpts) error {
	reader := bufio.NewReader(stdin)
	interactive := o.From == "" && !o.Yes

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	input := strings.TrimSpace(o.From)
	if input == "" {
		fmt.Println("keenetic-xray setup")
		fmt.Println("Paste a vless:// link, or a subscription http(s):// URL:")
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("reading input: %w", err)
		}
		input = strings.TrimSpace(line)
	}
	if input == "" {
		return fmt.Errorf("no vless:// link or subscription URL given")
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

	if interactive {
		fmt.Println("\nAvailable profiles:")
		for i, p := range profiles {
			fmt.Printf("  %d: %s -- %s:%d\n", i, p.Remark, p.Address, p.Port)
		}
	}

	var primaryIdx, backupIdx int
	if interactive {
		primaryIdx, err = promptIndex(reader, "Select PRIMARY", len(profiles), 0)
		if err != nil {
			return err
		}
		backupIdx = primaryIdx
		if len(profiles) > 1 {
			def := 1
			if primaryIdx == 1 {
				def = 0
			}
			if backupIdx, err = promptIndex(reader, "Select BACKUP", len(profiles), def); err != nil {
				return err
			}
		}
	} else {
		if primaryIdx, err = resolveProfileSelector(profiles, o.PrimarySel, 0); err != nil {
			return fmt.Errorf("--primary: %w", err)
		}
		defBackup := 0
		if len(profiles) > 1 {
			defBackup = 1
			if primaryIdx == 1 {
				defBackup = 0
			}
		}
		if backupIdx, err = resolveProfileSelector(profiles, o.BackupSel, defBackup); err != nil {
			return fmt.Errorf("--backup: %w", err)
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

	switch {
	case o.Proxy0 == "no":
		// leave Proxy0 alone
	case o.Proxy0 == "yes", !interactive && keenetic.Available():
		doSetupProxy0(cfg)
	case interactive:
		maybeSetupProxy0(reader, cfg)
	}

	if interactive {
		offerDaemonRestart(reader)
	} else {
		fmt.Println("apply with: /opt/etc/init.d/S99keenetic-xray restart")
	}
	return nil
}

// resolveProfileSelector turns a --primary/--backup value into an index:
// an integer index, or a case-insensitive substring of exactly one
// profile's remark. Empty selects def.
func resolveProfileSelector(profiles []config.Profile, sel string, def int) (int, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return def, nil
	}
	if n, err := strconv.Atoi(sel); err == nil {
		if n < 0 || n >= len(profiles) {
			return 0, fmt.Errorf("index %d out of range (0..%d)", n, len(profiles)-1)
		}
		return n, nil
	}
	match := -1
	low := strings.ToLower(sel)
	for i, p := range profiles {
		if strings.Contains(strings.ToLower(p.Remark), low) {
			if match >= 0 {
				return 0, fmt.Errorf("%q matches more than one profile", sel)
			}
			match = i
		}
	}
	if match < 0 {
		return 0, fmt.Errorf("no profile matches %q", sel)
	}
	return match, nil
}

// doSetupProxy0 performs the ndmc-side Proxy0 wiring and records it in the
// config. Router-only; a no-op where ndmc isn't present.
func doSetupProxy0(cfg *config.Config) {
	if !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		fmt.Println("  could not detect the router LAN IP:", err)
		fmt.Println("  run: keenetic-xray proxy0 set --lan-ip=192.168.x.1")
		return
	}
	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: cfg.Proxy0Port(),
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		fmt.Println("  Proxy0 setup failed:", err)
		return
	}
	cfg.Proxy0.Enabled = true
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  Proxy0 configured on the router but saving config failed:", err)
		return
	}
	fmt.Printf("  Proxy0 -> %s:%d. Assign devices/policies to Proxy0 in the Keenetic UI.\n", ip, cfg.Proxy0Port())
}

// maybeSetupProxy0 is the interactive prompt in front of doSetupProxy0.
func maybeSetupProxy0(reader *bufio.Reader, cfg *config.Config) {
	if !keenetic.Available() {
		return
	}
	fmt.Print("\nPoint Keenetic's Proxy0 at the proxy now (route the LAN through it)? [y/N]: ")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
		fmt.Println("skipped -- set it up later with: keenetic-xray proxy0 set")
		return
	}
	doSetupProxy0(cfg)
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
