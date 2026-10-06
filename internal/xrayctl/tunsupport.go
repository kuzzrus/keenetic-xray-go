package xrayctl

import (
	"context"
	"fmt"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// tunProbeDevice is the device name the support check puts in its config:
// one that can be no ndm interface and no operator's, so the check can never
// reach a real device. (xray opens the device in Handler.Start, which
// `-test` never reaches -- this is for a future core that does it earlier.)
const tunProbeDevice = "kxtunprobe"

// CheckTunSupport asks the xray-core at binary whether it knows the `tun`
// inbound: it builds a config holding only that inbound and a freedom
// outbound (no profile involved -- an AmneziaWG or naive primary needs
// things this check is not about) and runs `xray run -test` on it, which
// starts nothing and opens no device. Run before the router is touched, so
// a core from before the inbound existed is refused with xray's own message
// instead of being restarted into a crash loop.
func CheckTunSupport(ctx context.Context, binary string, mtu int) error {
	data, err := config.TunSupportProbeConfig(config.TunInboundOptions{Name: tunProbeDevice, MTU: mtu})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "keenetic-xray-tun-probe-*.json")
	if err != nil {
		return fmt.Errorf("temp file for the xray check: %w", err)
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("temp file for the xray check: %w", werr)
	}
	return ValidateConfig(ctx, binary, f.Name(), nil)
}
