package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
)

// xrayCoreVersion runs `<xray> version` and returns its first line, e.g.
// "Xray 26.3.27 (Xray, Penetrates Everything.) ...".
func xrayCoreVersion() (string, error) {
	out, err := exec.Command(xrayBinaryPath(), "version").Output()
	if err != nil {
		return "", err
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if first == "" {
		return "", fmt.Errorf("%s version printed nothing", xrayBinaryPath())
	}
	return first, nil
}

func cmdStatus(args []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	fmt.Printf("variant: %s\n", cfg.Variant)
	fmt.Printf("profiles: %d\n", len(cfg.Profiles))
	if p := cfg.Primary(); p != nil {
		fmt.Printf("primary: %s (%s:%d)\n", p.Remark, p.Address, p.Port)
	} else {
		fmt.Println("primary: not set")
	}
	if b := cfg.Backup(); b != nil {
		fmt.Printf("backup: %s (%s:%d)\n", b.Remark, b.Address, b.Port)
	} else {
		fmt.Println("backup: not set")
	}
	if cfg.Subscription != nil {
		fmt.Printf("subscription: %s\n", cfg.Subscription.URL)
	}
	fmt.Printf("agent enabled: %v\n", cfg.Agent.Enabled)
	if line, err := xrayCoreVersion(); err != nil {
		fmt.Printf("xray-core: not installed (%v)\n", err)
	} else {
		fmt.Printf("xray-core: %s\n", line)
	}
	fmt.Println("note: this reports saved configuration, not live daemon state (no IPC layer yet)")
	return nil
}

func cmdDoctor(args []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	problems := 0
	check := func(ok bool, msg string) {
		if ok {
			fmt.Println("[ok]  ", msg)
		} else {
			fmt.Println("[FAIL]", msg)
			problems++
		}
	}

	check(len(cfg.Profiles) > 0, "at least one profile configured")
	check(cfg.Primary() != nil, "primary profile selected")
	check(cfg.Backup() != nil, "backup profile selected")
	if err := cfg.Validate(); err != nil {
		check(false, fmt.Sprintf("config validates: %v", err))
	} else {
		check(true, "config validates")
	}

	if line, err := xrayCoreVersion(); err != nil {
		check(false, fmt.Sprintf("xray-core runnable at %s (%v) -- run: keenetic-xray internal ensure-xray-core", xrayBinaryPath(), err))
	} else {
		check(true, "xray-core: "+line)
	}

	if free, err := diskspace.FreeBytes(optPath()); err != nil {
		fmt.Println("[warn] could not determine free disk space:", err)
	} else {
		fmt.Printf("[info] free space at %s: %d MB\n", optPath(), free/1024/1024)
	}

	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Println("all checks passed")
	return nil
}
