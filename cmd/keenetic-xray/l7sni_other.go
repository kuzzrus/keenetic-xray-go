//go:build !linux

// Stub for every platform other than Linux -- see l7sni_linux.go's own
// doc comment for why. Keeps this package buildable on the Windows box
// this project is developed on; the real implementation only ever runs
// on the Linux routers this project actually targets.

package main

import (
	"context"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func l7SNIClassifyLoop(ctx context.Context, logf func(string, ...any)) {}

func reconcileL7SNI(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {}
