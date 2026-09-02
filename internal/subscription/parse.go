package subscription

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// Parse splits decoded subscription content into lines and parses each
// vless:// line into a config.Profile. Lines using another scheme
// (vmess://, trojan://, ss://, ...) or that fail to parse are skipped and
// reported as warnings rather than aborting the whole refresh -- one
// malformed or unsupported entry in an otherwise-valid list shouldn't
// lose the rest.
func Parse(decoded []byte) (profiles []config.Profile, warnings []string) {
	scanner := bufio.NewScanner(bytes.NewReader(decoded))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "vless://") {
			scheme, _, _ := strings.Cut(line, "://")
			warnings = append(warnings, fmt.Sprintf("skipped non-vless entry (%s://)", scheme))
			continue
		}
		p, err := config.ParseVLESSURI(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped malformed vless entry: %v", err))
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, warnings
}
