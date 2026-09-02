// Command keenetic-xray-control-server is the VPS-side counterpart to
// keenetic-xray's `agent` subcommand: it queues commands for polling
// router agents and exposes them through a Telegram bot. It is not part
// of the router installer, shares no deployment with it, and never runs
// on a router.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keenetic-xray-control-server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version") {
		fmt.Println(version.String())
		return nil
	}

	configPath := envOr("KEENETIC_XRAY_CS_CONFIG", defaultConfigPath)

	if len(args) >= 1 && args[0] == "setup" {
		return cmdSetup(configPath)
	}

	cfg, err := loadSettings(configPath)
	if err != nil {
		return err
	}

	cert, err := botcontrol.LoadOrGenerateCert(cfg.CertPath, cfg.KeyPath, "keenetic-xray-control-server")
	if err != nil {
		return fmt.Errorf("loading/generating TLS certificate: %w", err)
	}
	fingerprint, err := botcontrol.FingerprintSHA256(cert)
	if err != nil {
		return fmt.Errorf("computing certificate fingerprint: %w", err)
	}

	store, err := botcontrol.LoadStore(cfg.QueuePath)
	if err != nil {
		return fmt.Errorf("loading queue store: %w", err)
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	server := botcontrol.NewServer(botcontrol.ServerConfig{
		Store:       store,
		Auth:        botcontrol.StaticRouterAuth(cfg.Routers),
		Fingerprint: fingerprint,
		Logger:      logger,
	})

	allowedChats := make(map[int64]bool, len(cfg.AllowedChatIDs))
	for _, id := range cfg.AllowedChatIDs {
		allowedChats[id] = true
	}
	knownRouters := make([]string, 0, len(cfg.Routers))
	for id := range cfg.Routers {
		knownRouters = append(knownRouters, id)
	}
	bot := &botcontrol.TelegramBot{
		Token:        cfg.TelegramToken,
		AllowedChats: allowedChats,
		KnownRouters: knownRouters,
		Store:        store,
		Logger:       logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		logger.Println("shutting down...")
		cancel()
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- botcontrol.ListenAndServeTLS(ctx, cfg.ListenAddr, cert, server) }()
	go func() { errCh <- bot.Run(ctx) }()

	logger.Printf("listening on %s (fingerprint %s, %d router(s) registered)", cfg.ListenAddr, fingerprint, len(cfg.Routers))

	firstErr := <-errCh
	shuttingDown := ctx.Err() != nil // true if the signal handler already cancelled ctx
	cancel()
	<-errCh // wait for the other goroutine to notice cancellation and exit before returning

	if firstErr != nil && !shuttingDown {
		return firstErr
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
