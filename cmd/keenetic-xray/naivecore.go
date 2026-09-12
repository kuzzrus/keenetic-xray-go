package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/naivecore"
)

// cmdEnsureNaiveCore installs a runnable `naive` binary if one isn't
// already present -- the mirrored build from this project's
// naive-core/<ver> releases. Unlike xray-core there's no opkg fallback
// (naive isn't in any Entware feed) and no per-router version pin to
// persist yet: this just fetches naivecore.PinnedVersion.
//
//	--force   reinstall even if naive already runs at the destination
func cmdEnsureNaiveCore(args []string) error {
	force := false
	for _, a := range args {
		if a == "--force" {
			force = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	src, err := naivecore.Ensure(ctx, naivecore.Options{
		Dest:    naiveBinaryPath(),
		Force:   force,
		BaseURL: os.Getenv("KEENETIC_XRAY_NAIVE_BASE_URL"), // "" -> the real release URL; overridable for tests
	})
	if err != nil {
		return fmt.Errorf("ensuring naive: %w", err)
	}
	fmt.Printf("naive ready (%s, %s) at %s\n", src, naivecore.PinnedVersion, naiveBinaryPath())
	return nil
}
