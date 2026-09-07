package addons

import "github.com/kuzzrus/keenetic-xray-go/internal/keenetic"

// Seam for the router-CLI calls an addon needs: flipping `opkg
// dns-override` so the unbound component can (un)wire itself as the
// router's resolver, and the ndmc-present check. Injectable like
// sys.go's vars so the component tests run without a Keenetic.
var (
	setRouterDNSOverride = keenetic.SetOpkgDNSOverride    // func(ctx, on bool) error
	routerDNSOverrideOn  = keenetic.OpkgDNSOverrideActive // func(ctx) (bool, error)
	keeneticAvailable    = keenetic.Available             // func() bool
)
