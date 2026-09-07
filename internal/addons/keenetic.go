package addons

import "github.com/kuzzrus/keenetic-xray-go/internal/keenetic"

// Seam for the router-CLI calls the unbound component needs for its
// router-DNS mode. Injectable like sys.go's vars so the tests run
// without a Keenetic.
var (
	setLocalNameServer    = keenetic.SetLocalNameServer    // func(ctx, ip string, port int, on bool) error
	localNameServerActive = keenetic.LocalNameServerActive // func(ctx, ip string, port int) (bool, error)
	keeneticLANIP         = keenetic.LANIP                 // func(ctx, override string) (string, error)
	keeneticAvailable     = keenetic.Available             // func() bool
)
