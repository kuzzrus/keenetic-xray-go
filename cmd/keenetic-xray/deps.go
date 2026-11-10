package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
)

// The two calls the commands make into featuredeps, as variables so the
// enabling commands and the daemon's start-up can be tested without opkg or a
// router.
var (
	featureMissing        = featuredeps.Missing
	featureEnsure         = featuredeps.Ensure
	featureEnsureRequired = featuredeps.EnsureRequired
)

// ensureFeatureDeps is what an enabling command runs before it changes
// anything: it makes sure the tools the feature needs are on the router, says
// what it installed and which optional ones it could not install, and returns an
// error when one the feature cannot work without is missing -- the command then
// leaves the feature off instead of saving a setting that cannot work.
func ensureFeatureDeps(f featuredeps.Feature) error { return ensureFeatureDepsTo(os.Stdout, f) }

// ensureFeatureDepsTo is ensureFeatureDeps writing to w.
//
// A cold `opkg update` can take a minute or two, so what is about to happen is
// said first: the terminal would otherwise look hung.
func ensureFeatureDepsTo(w io.Writer, f featuredeps.Feature) error {
	if missing := featureMissing(f); len(missing) > 0 {
		fmt.Fprintf(w, "не хватает: %s — ставлю через opkg (может занять пару минут) …\n", featuredeps.Names(missing))
	}
	ctx, cancel := context.WithTimeout(context.Background(), featuredeps.Timeout)
	defer cancel()
	res := featureEnsure(ctx, f)
	for _, line := range res.Lines("", "предупреждение: ") {
		fmt.Fprintln(w, line)
	}
	return res.Err()
}

// optionalTried records the features whose optional tools this process has
// already tried to install.
var optionalTried sync.Map

// ensureOptionalInBackground installs the optional tools of f (conntrack) once
// per process, in the background, and logs what happened. For the daemon's own
// start-up paths: they check the REQUIRED tools synchronously and must never
// wait for, or keep retrying, something the feature works without.
func ensureOptionalInBackground(f featuredeps.Feature, prefix string, logf func(string, ...any)) {
	if _, tried := optionalTried.LoadOrStore(f, struct{}{}); tried {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), featuredeps.Timeout)
		defer cancel()
		for _, line := range featureEnsure(ctx, f).Lines("", "") {
			logf("%s: %s", prefix, line)
		}
	}()
}
