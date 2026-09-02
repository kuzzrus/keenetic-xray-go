package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func cmdAgent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray agent {configure|enable|disable|status} ...")
	}
	switch args[0] {
	case "configure":
		return agentConfigure(args[1:])
	case "enable":
		return agentSetEnabled(true)
	case "disable":
		return agentSetEnabled(false)
	case "status":
		return agentStatus()
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}

func agentConfigure(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: keenetic-xray agent configure <control-server-url> <router-id> <fingerprint-sha256> <token>")
	}
	serverURL, routerID, fingerprint, token := args[0], args[1], args[2], args[3]

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	tokenFile := cfg.Agent.TokenFile
	if tokenFile == "" {
		tokenFile = defaultAgentTokenPath()
	}
	// Token lives in its own 0600 file, never in config.json -- doctor
	// and any future config dumps must never be able to leak it.
	if err := os.WriteFile(tokenFile, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return fmt.Errorf("writing token file %s: %w", tokenFile, err)
	}

	cfg.Agent.ControlServerURL = serverURL
	cfg.Agent.RouterID = routerID
	cfg.Agent.FingerprintSHA256 = fingerprint
	cfg.Agent.TokenFile = tokenFile

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("agent configured; run `keenetic-xray agent enable` to turn it on")
	return nil
}

func agentSetEnabled(enabled bool) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if enabled {
		if cfg.Variant != config.VariantFull {
			return fmt.Errorf("remote control agent requires the Full variant (current: %s) -- see docs/full-vs-mini.md", cfg.Variant)
		}
		if cfg.Agent.ControlServerURL == "" || cfg.Agent.RouterID == "" || cfg.Agent.FingerprintSHA256 == "" || cfg.Agent.TokenFile == "" {
			return fmt.Errorf("agent is not configured -- run `keenetic-xray agent configure` first")
		}
	}
	cfg.Agent.Enabled = enabled
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("agent enabled: %v\n", enabled)
	return nil
}

func agentStatus() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	fmt.Printf("enabled: %v\n", cfg.Agent.Enabled)
	fmt.Printf("control server: %s\n", orNotSet(cfg.Agent.ControlServerURL))
	fmt.Printf("router id: %s\n", orNotSet(cfg.Agent.RouterID))
	fmt.Printf("fingerprint: %s\n", orNotSet(cfg.Agent.FingerprintSHA256))
	if cfg.Agent.TokenFile == "" {
		fmt.Println("token file: not set")
	} else if _, err := os.Stat(cfg.Agent.TokenFile); err == nil {
		fmt.Printf("token file: %s (present)\n", cfg.Agent.TokenFile)
	} else {
		fmt.Printf("token file: %s (MISSING)\n", cfg.Agent.TokenFile)
	}
	return nil
}

func orNotSet(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

// loadAgentOptions builds botcontrol.AgentOptions from cfg, reading the
// token from its own file rather than config.json.
func loadAgentOptions(cfg *config.Config) (botcontrol.AgentOptions, error) {
	tokenBytes, err := os.ReadFile(cfg.Agent.TokenFile)
	if err != nil {
		return botcontrol.AgentOptions{}, fmt.Errorf("reading agent token file %s: %w", cfg.Agent.TokenFile, err)
	}
	return botcontrol.AgentOptions{
		ControlServerURL:  cfg.Agent.ControlServerURL,
		RouterID:          cfg.Agent.RouterID,
		Token:             strings.TrimSpace(string(tokenBytes)),
		FingerprintSHA256: cfg.Agent.FingerprintSHA256,
	}, nil
}
