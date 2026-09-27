package main

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
)

// teeStdio routes os.Stdout and os.Stderr through pipes that copy
// everything to where they pointed before *and* into dlog, and returns a
// func undoing it that waits for the copies to drain -- call it on the
// way out, after the last write. ok is false if nothing could be teed
// (no log file, or no pipes), and then logf has to write to dlog itself.
//
// 2026-09-27 external review, BOOT-04: much of what the daemon says goes
// straight to stdout/stderr rather than through logf --
// internal/failover's start retries and mode lines, reload errors,
// "agent stopped". The init script sends stdout to /dev/null (it would
// only repeat daemon.log) and stderr to boot.log; before this none of it
// ever reached daemon.log, the one log `keenetic-xray logs` and the bot
// show. Go's own panic output goes to file descriptor 2, not through
// os.Stderr, so it still lands in boot.log exactly as before.
func teeStdio(dlog *applog.Writer) (restore func(), ok bool) {
	if dlog == nil {
		return func() {}, false
	}
	restoreOut, okOut := teeFile(&os.Stdout, dlog)
	restoreErr, okErr := teeFile(&os.Stderr, dlog)
	return func() { restoreErr(); restoreOut() }, okOut && okErr
}

func teeFile(f **os.File, dlog *applog.Writer) (restore func(), ok bool) {
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}, false
	}
	orig := *f
	*f = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				// Each side best-effort and independent: a terminal that
				// went away (a foreground `keenetic-xray daemon` whose SSH
				// session closed) must not stop the copy -- a stalled pipe
				// would block every later write to stdout, the whole
				// daemon's logging with it.
				_, _ = orig.Write(buf[:n])
				_, _ = dlog.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return func() {
		*f = orig
		_ = w.Close()
		<-done
		_ = r.Close()
	}, true
}

// sysLog puts msg in the router's own system log (the Keenetic web UI's
// journal) via busybox `logger`, best-effort. For the one thing that must
// be findable even when /opt's own logs are not: why the daemon stopped.
func sysLog(msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "logger", "-t", "keenetic-xray", msg).Run()
}

// drainEvents consumes ch until ctx ends, for a producer whose consumer
// never started -- see the agent's call site in cmdDaemon.
func drainEvents(ctx context.Context, ch <-chan botcontrol.Event) {
	for {
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}
}
