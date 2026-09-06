//go:build !unix

package main

import "context"

// watchReconcileSignal is a no-op off Unix -- SIGUSR1 and the netfilter.d
// hook only exist on the router. Keeps the Windows dev build green.
func watchReconcileSignal(ctx context.Context, run func()) {}
