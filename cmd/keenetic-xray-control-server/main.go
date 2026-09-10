// Command keenetic-xray-control-server is the VPS-side counterpart to
// keenetic-xray's `agent` subcommand: it queues commands for polling
// router agents and exposes them through a Telegram bot. It is not part
// of the router installer, shares no deployment with it, and never runs
// on a router.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
	"golang.org/x/crypto/acme/autocert"
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

	// tlsConfig serves the self-signed cert generated/loaded above by
	// default; with a domain configured, ACME-issued certs join it via
	// SNI so already-pinned agents and newly-migrated domain agents are
	// both served correctly off the same listener (see dualCertGetter).
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	var acmeMgr *autocert.Manager
	if cfg.Domain != "" {
		acmeMgr = newAutocertManager(cfg.Domain, cfg.AutocertCacheDir)
		tlsConfig = &tls.Config{GetCertificate: dualCertGetter(cert, cfg.Domain, acmeMgr)}
	}

	store, err := botcontrol.LoadStore(cfg.QueuePath)
	if err != nil {
		return fmt.Errorf("loading queue store: %w", err)
	}

	// Carry any routers pinned in config.json into the runtime registry
	// (once; a no-op for IDs already there). After this the registry --
	// mutable from the bot with /add_router and /remove_router -- is the
	// source of truth for which routers may authenticate.
	for id, token := range cfg.Routers {
		if err := store.SeedRouter(id, token, ""); err != nil {
			return fmt.Errorf("seeding router %q from config: %w", id, err)
		}
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	allowedChats := make(map[int64]bool, len(cfg.AllowedChatIDs))
	for _, id := range cfg.AllowedChatIDs {
		allowedChats[id] = true
	}
	bot := &botcontrol.TelegramBot{
		Token:        cfg.TelegramToken,
		AllowedChats: allowedChats,
		Store:        store,
		Fingerprint:  fingerprint,
		Domain:       cfg.Domain,
		ServerURL:    cfg.PublicURL,
		ListenAddr:   cfg.ListenAddr,
		Logger:       logger,
		// The systemd .path unit installed by server-install.sh watches
		// this file; touching it kicks off the root self-update.
		SelfUpdatePath: filepath.Join(filepath.Dir(cfg.QueuePath), "update.request"),
	}

	// Best-effort: announce a just-completed self-update (see
	// notifyIfUpdated) -- never fatal to starting up.
	versionFile := filepath.Join(filepath.Dir(cfg.QueuePath), "last_version.txt")
	if err := notifyIfUpdated(versionFile, bot.NotifyServer); err != nil {
		logger.Println("version-change check failed:", err)
	}

	// The agent pushes failover/daemon-start events to /agent/event; the
	// bot fans them out to the allowed chats.
	server := botcontrol.NewServer(botcontrol.ServerConfig{
		Store:       store,
		Auth:        store,
		Fingerprint: fingerprint,
		Logger:      logger,
		OnEvent:     bot.NotifyEvent,
	})

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
	go func() { errCh <- botcontrol.ListenAndServeTLSDynamic(ctx, cfg.ListenAddr, tlsConfig, server) }()
	go func() { errCh <- bot.Run(ctx) }()
	go (&botcontrol.OfflineWatcher{Store: store, Notify: bot.NotifyOffline}).Run(ctx)

	if acmeMgr != nil {
		// Let's Encrypt's HTTP-01 challenge always dials :80, regardless
		// of cfg.ListenAddr -- a second, plain-HTTP listener just for
		// that. Fire-and-forget like OfflineWatcher above: nothing here
		// holds state worth a graceful drain, so an ungraceful stop on
		// process exit is fine; only log if it fails outright (most
		// likely cause: nothing granted CAP_NET_BIND_SERVICE for :80).
		go func() {
			if err := http.ListenAndServe(":80", acmeMgr.HTTPHandler(nil)); err != nil && ctx.Err() == nil {
				logger.Printf("acme: :80 challenge listener failed (Let's Encrypt can't reach it to issue/renew for %s): %v", cfg.Domain, err)
			}
		}()
		logger.Printf("listening on %s and :80 (domain %s, ACME cert + fingerprint %s fallback, %d router(s) registered)",
			cfg.ListenAddr, cfg.Domain, fingerprint, len(store.Routers()))
	} else {
		logger.Printf("listening on %s (fingerprint %s, %d router(s) registered)", cfg.ListenAddr, fingerprint, len(store.Routers()))
	}

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
