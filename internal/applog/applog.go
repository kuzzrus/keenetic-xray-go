// Package applog is a tiny size-capped append log: the failover daemon
// writes its own lines (and xray's stderr) here so `keenetic-xray logs`
// and the bot's 📜 Логи can show recent activity without SSH. Not a
// general logging framework -- one file, one cap, plain lines.
package applog

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMaxBytes is the size a Writer keeps its file under. When a write
// would exceed it, the file is trimmed to roughly the newest half.
const DefaultMaxBytes = 256 << 10

// Writer is an io.Writer that appends to a file and self-trims once it
// grows past MaxBytes (keeping the tail). Safe for concurrent use.
type Writer struct {
	path     string
	maxBytes int64

	mu sync.Mutex
	f  *os.File
}

// New opens (creating, appending) path. A failure to open is returned;
// callers that treat the log as best-effort can ignore it and pass a nil
// *Writer to Tee.
func New(path string, maxBytes int64) (*Writer, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{path: path, maxBytes: maxBytes, f: f}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.f.Write(p)
	if err != nil {
		return n, err
	}
	if fi, serr := w.f.Stat(); serr == nil && fi.Size() > w.maxBytes {
		w.trimLocked()
	}
	return n, nil
}

// trimLocked rewrites the file keeping about the newest half, starting at
// the first newline after the cut so the first surviving line is whole.
func (w *Writer) trimLocked() {
	if err := w.f.Sync(); err != nil {
		return
	}
	all, err := os.ReadFile(w.path)
	if err != nil {
		return
	}
	keep := int(w.maxBytes / 2)
	if len(all) <= keep {
		return
	}
	buf := all[len(all)-keep:]
	if i := bytes.IndexByte(buf, '\n'); i >= 0 && i+1 < len(buf) {
		buf = buf[i+1:]
	}
	tmp := w.path + ".trim"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return
	}
	// Close before rename: Windows can't replace an open file (Linux, the
	// only place the daemon runs, wouldn't care). Reopen either way.
	_ = w.f.Close()
	renameErr := os.Rename(tmp, w.path)
	if renameErr != nil {
		os.Remove(tmp)
	}
	nf, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return // w.f is closed now; subsequent Writes will error -- acceptable, log is best-effort
	}
	w.f = nf
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// Tee returns w if non-nil, otherwise a writer that only goes to also.
// Handy for `logf := ... io.MultiWriter(os.Stdout, applog.Tee(w))`.
func Tee(w *Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// Tail returns the last n lines of the file at path (fewer if the file is
// shorter), oldest first. A missing file yields "" with no error.
func Tail(path string, n int) (string, error) {
	if n <= 0 {
		n = 1
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	data = bytes.TrimRight(data, "\n")
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return string(bytes.Join(lines, []byte("\n"))), nil
}
