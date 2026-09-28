//go:build linux

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// shellFuncs cuts the named top-level functions out of a shell script,
// so a test can run them without the script's own top-level code.
func shellFuncs(t *testing.T, src string, names ...string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range names {
		re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{\n.*?^\}\n`)
		fn := re.FindString(src)
		if fn == "" {
			t.Fatalf("function %s() not found", name)
		}
		b.WriteString(fn)
	}
	return b.String()
}

// fakeCurl logs every call and succeeds only when its arguments contain
// $CURL_OK_WHEN; a failing call first prints half a body to stdout, the
// way a download cut off mid-way does.
const fakeCurl = `#!/bin/sh
echo "$*" >> "$CURL_LOG"
case "$*" in
  *"$CURL_OK_WHEN"*) ;;
  *) printf 'partial'; exit 7 ;;
esac
out=
while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
if [ -n "$out" ]; then echo body > "$out"; else echo body; fi
`

// TestInstallFetch_Ladder runs install.sh's own fetch(): as is, then
// `-4 --curves X25519`, then through the tunnel -- stopping at the first
// that works, and never letting a failed try's partial output through.
func TestInstallFetch_Ladder(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	funcs := shellFuncs(t, string(src), "fetch", "fetch_curl", "curl_once", "tunnel_proxy")

	cases := []struct {
		name    string
		okWhen  string
		proxy   string
		wantOK  bool
		wantTry int
	}{
		{"direct works", "-fsSL", "socks5h://127.0.0.1:1080", true, 1},
		{"small hello works", "--curves X25519", "socks5h://127.0.0.1:1080", true, 2},
		{"tunnel works", "--proxy socks5h://127.0.0.1:1080", "socks5h://127.0.0.1:1080", true, 3},
		{"no tunnel on a first install", "--proxy", "", false, 2},
		{"nothing works", "never", "socks5h://127.0.0.1:1080", false, 3},
	}
	for _, tc := range cases {
		for _, toFile := range []bool{true, false} {
			name := tc.name + "/stdout"
			if toFile {
				name = tc.name + "/file"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(fakeCurl), 0o755); err != nil {
					t.Fatal(err)
				}
				out := ""
				if toFile {
					out = filepath.Join(dir, "out")
				}
				log := filepath.Join(dir, "curl.log")
				sh := shell()
				script := "set -eu\n" + funcs + "fetch https://example.invalid/x \"$OUT\"\n"
				cmd := exec.Command(sh[0], append(sh[1:], "-c", script)...)
				cmd.Env = append(os.Environ(),
					"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
					"CURL_LOG="+log, "CURL_OK_WHEN="+tc.okWhen, "OUT="+out,
					"KEENETIC_XRAY_FETCH_PROXY="+tc.proxy)
				stdout, runErr := cmd.Output()
				if (runErr == nil) != tc.wantOK {
					t.Fatalf("fetch succeeded = %v, want %v (%v)", runErr == nil, tc.wantOK, runErr)
				}
				tries, _ := os.ReadFile(log)
				if n := strings.Count(string(tries), "\n"); n != tc.wantTry {
					t.Errorf("%d curl calls, want %d:\n%s", n, tc.wantTry, tries)
				}
				if !tc.wantOK {
					return
				}
				got := string(stdout)
				if toFile {
					b, _ := os.ReadFile(out)
					got = string(b)
				}
				if got != "body\n" {
					t.Errorf("fetched %q, want just the successful try's body", got)
				}
			})
		}
	}
}
