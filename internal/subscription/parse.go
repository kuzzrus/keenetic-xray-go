package subscription

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// Parse splits decoded subscription content into lines and parses each
// vless:// or naive+https:// line into a config.Profile via
// config.ParseProfileURI. Lines using another scheme (vmess://, trojan://,
// ss://, ...) or that fail to parse are skipped and reported as warnings
// rather than aborting the whole refresh -- one malformed or unsupported
// entry in an otherwise-valid list shouldn't lose the rest.
func Parse(decoded []byte) (profiles []config.Profile, warnings []string) {
	scanner := bufio.NewScanner(bytes.NewReader(decoded))
	// SUB-01: bufio.Scanner's default 64KB max token size fails closed,
	// not open -- once a line exceeds it, Scan() just returns false as
	// if EOF had been reached, silently discarding every line after it
	// (and, before this fix, nothing even checked Err() afterward, so
	// the truncation was invisible -- a partial subscription looked
	// exactly like a normal, complete one). A vless:// line this long is
	// atypical, but nothing bounds an entry's length on the subscription
	// server's side. Raised to MaxBodyBytes, fetch.go's own cap on the
	// *entire* response body -- safe precisely because no single line
	// can ever legitimately be longer than a response that already
	// passed that check.
	scanner.Buffer(make([]byte, 0, 64*1024), MaxBodyBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		p, err := config.ParseProfileURI(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped entry: %v", err))
			continue
		}
		profiles = append(profiles, p)
	}
	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("subscription content truncated: %v (remaining entries may be missing)", err))
	}
	return profiles, warnings
}
