package addons

import (
	"context"
	"errors"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/naivecore"
)

func init() { Register(naiveCoreAddon{}) }

// naiveCoreBinary is where the vendored `naive` binary lives -- same
// default cmd/keenetic-xray's naiveBinaryPath() uses. Unlike that
// package's KEENETIC_XRAY_NAIVE_BINARY override, this addon (like every
// other one in this package) always targets the real, fixed path; it has
// no reason to run against a test-relocated binary outside its own tests.
const naiveCoreBinary = "/opt/sbin/naive"

// naiveEnsure / naiveVersion are naivecore.Ensure/Version, swappable in
// tests -- same injectable-var convention as sys.go, for the one call in
// this package that reaches the network instead of opkg/init.d.
var (
	naiveEnsure  = naivecore.Ensure
	naiveVersion = naivecore.Version
)

// naiveCoreAddon is the vendored NaiveProxy client binary (internal/
// naivecore), not a daemon this package starts or stops: whether it's
// actually running as a sidecar right now is failover's call (a naive
// profile going live), not addons'. This just tracks whether the binary
// is present and lets it be installed/removed like any other component.
type naiveCoreAddon struct{}

func (naiveCoreAddon) ID() string { return "naive-core" }
func (naiveCoreAddon) Title() string {
	return "naive-core — бинарь для egress-сайдкара NaiveProxy"
}

func (naiveCoreAddon) About() string {
	return "Клиент NaiveProxy (klzgrad/naiveproxy) -- отдельный процесс, через который идёт " +
		"трафик профиля с naive+https:// ссылкой (Protocol=naive): HTTP/2 CONNECT с TLS-отпечатком " +
		"настоящего Chrome и паддингом кадров, для интеропа с готовым Caddy+forward_proxy сервером. " +
		"Нужен, только если такой профиль настроен как primary или backup -- без него переключение " +
		"на naive-профиль ошибётся с понятной причиной. Настроек нет; версия зафиксирована в " +
		"packaging/naive-core/version."
}

func (naiveCoreAddon) Detect(ctx context.Context) State {
	v, err := naiveVersion(naiveCoreBinary)
	return State{Installed: err == nil, Version: v}
}

func (naiveCoreAddon) Install(ctx context.Context) error {
	_, err := naiveEnsure(ctx, naivecore.Options{Dest: naiveCoreBinary})
	return err
}

func (naiveCoreAddon) Remove(ctx context.Context) error {
	if err := removeFile(naiveCoreBinary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (naiveCoreAddon) Configure(context.Context, map[string]string) error { return errNoConfig }

func (naiveCoreAddon) Status(ctx context.Context) (string, error) {
	if v, err := naiveVersion(naiveCoreBinary); err == nil {
		return v + " установлен -- доступен как egress-сайдкар для naive-профилей", nil
	}
	return "naive-core не установлен -- переключение на naive-профиль (primary или backup) не сработает, " +
		"пока не поставишь (или пока это не сделает keenetic-xray internal ensure-naive-core)", nil
}
