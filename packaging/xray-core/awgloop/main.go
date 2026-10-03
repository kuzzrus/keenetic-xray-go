//go:build ignore

// Loopback AmneziaWG end-to-end harness for a patched Xray-core -- verifies an
// amneziawg-<tag>.patch WITHOUT a router. Not part of this module's build
// (build-ignored); copy it into a patched Xray-core checkout and run it there.
//
//	git clone -c core.autocrlf=false --depth 1 --branch <tag> https://github.com/XTLS/Xray-core
//	cd Xray-core
//	git apply <this repo>/packaging/xray-core/amneziawg-<tag>.patch
//	protoc --go_out=. --go_opt=paths=source_relative -I. proxy/wireguard/config.proto
//	go build -o xray ./main
//	mkdir awgloop && cp <this repo>/packaging/xray-core/awgloop/main.go awgloop/
//	go run awgloop/main.go -xray ./xray
//
// For every scenario it starts an AmneziaWG *server* peer entirely in
// userspace (the vendored amneziawg-go fork + its gVisor netstack TUN, with
// an HTTP server inside the tunnel), writes an xray client config shaped like
// internal/config's buildAmneziaWGOutbound output, runs the patched xray as a
// subprocess, and fetches a page *through the tunnel* via xray's SOCKS inbound.
// The server enforces its own obfuscation parameters, so a handshake only
// succeeds if the client really wrote matching AWG parameters into the device.
//
// What it catches: put the old receive-side bug back (proxy/wireguard/bind.go
// zeroing bytes 1-3 of every received packet, see docs/HANDOFF-amneziawg.md)
// and the AWG scenarios go red with "Received message with unknown type".
// What it cannot: a real AWG server's quirks -- that still needs a router.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

type scenario struct {
	name      string
	serverAWG map[string]string
	clientAWG map[string]string
	wantOK    bool
}

var (
	awgClassic = map[string]string{
		"jc": "5", "jmin": "10", "jmax": "50",
		"s1": "20", "s2": "30",
		"h1": "1020304051", "h2": "1020304052", "h3": "1020304053", "h4": "1020304054",
	}
	awgV2 = map[string]string{
		"jc": "5", "jmin": "10", "jmax": "50",
		"s1": "20", "s2": "30", "s3": "12", "s4": "8",
		"h1": "100000-800000", "h2": "1000000-8000000",
		"h3": "10000000-80000000", "h4": "100000000-800000000",
		"i1": "<b 0xc7000000010a><r 20>",
	}
	awgOtherH = map[string]string{
		"jc": "5", "jmin": "10", "jmax": "50",
		"s1": "20", "s2": "30",
		"h1": "1020304051", "h2": "1020304052", "h3": "1020304053", "h4": "1999999999",
	}
)

func main() {
	xrayBin := flag.String("xray", "", "path to the patched xray binary")
	only := flag.String("only", "", "run only scenarios whose name contains this")
	flag.Parse()
	if *xrayBin == "" {
		fmt.Println("need -xray")
		os.Exit(2)
	}

	scenarios := []scenario{
		{"plain WireGuard both sides (sanity)", nil, nil, true},
		{"AWG classic (jc/jmin/jmax/s1/s2/h1-h4) both sides", awgClassic, awgClassic, true},
		{"AWG 2.0 style (s3/s4, h ranges, i1) both sides", awgV2, awgV2, true},
		{"NEGATIVE: server AWG, client plain -> must fail", awgClassic, nil, false},
		{"NEGATIVE: AWG with mismatched h4 -> must fail", awgClassic, awgOtherH, false},
	}

	failed := 0
	for i, sc := range scenarios {
		if *only != "" && !strings.Contains(sc.name, *only) {
			continue
		}
		ok, detail := run(*xrayBin, sc, i)
		verdict := "PASS"
		if ok != sc.wantOK {
			verdict = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %-58s tunnel-request-ok=%v (want %v)\n", verdict, sc.name, ok, sc.wantOK)
		if verdict == "FAIL" || os.Getenv("AWGLOOP_VERBOSE") != "" {
			fmt.Println(indent(detail))
		}
	}
	if failed > 0 {
		fmt.Printf("\n%d scenario(s) did not behave as expected\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nall scenarios behaved as expected")
}

func run(xrayBin string, sc scenario, idx int) (bool, string) {
	srvPriv, srvPub := keypair()
	cliPriv, cliPub := keypair()
	udpPort := freeUDPPort()
	socksPort := freeTCPPort()

	// ---- server peer, userspace ----
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		return false, "server tun: " + err.Error()
	}
	dev := device.NewDevice(tdev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "srv: "))
	defer dev.Close()
	var u strings.Builder
	fmt.Fprintf(&u, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(srvPriv), udpPort)
	for _, k := range sortedKeys(sc.serverAWG) {
		fmt.Fprintf(&u, "%s=%s\n", k, sc.serverAWG[k])
	}
	fmt.Fprintf(&u, "public_key=%s\nallowed_ip=10.77.0.2/32\n", hex.EncodeToString(cliPub))
	if err := dev.IpcSet(u.String()); err != nil {
		return false, "server IpcSet: " + err.Error()
	}
	if err := dev.Up(); err != nil {
		return false, "server Up: " + err.Error()
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		return false, "server listen: " + err.Error()
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "AWG-LOOP-OK")
	}))

	// ---- xray client config, same shape as buildAmneziaWGOutbound ----
	settings := map[string]any{
		"IsClient":  true,
		"secretKey": base64.StdEncoding.EncodeToString(cliPriv),
		"address":   []string{"10.77.0.2/32"},
		"mtu":       1280,
		"peers": []map[string]any{{
			"publicKey":  base64.StdEncoding.EncodeToString(srvPub),
			"endpoint":   fmt.Sprintf("127.0.0.1:%d", udpPort),
			"allowedIPs": []string{"0.0.0.0/0", "::/0"},
			"keepAlive":  25,
		}},
	}
	for k, v := range sc.clientAWG {
		settings[k] = v
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []map[string]any{{
			"tag": "in", "listen": "127.0.0.1", "port": socksPort,
			"protocol": "socks", "settings": map[string]any{"auth": "noauth"},
		}},
		"outbounds": []map[string]any{{"tag": "proxy", "protocol": "wireguard", "settings": settings}},
	}
	dir, _ := os.MkdirTemp("", fmt.Sprintf("awgloop-%d-", idx))
	cfgPath := filepath.Join(dir, "client.json")
	b, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, b, 0o600)

	var logBuf lockedBuffer
	cmd := exec.Command(xrayBin, "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = &logBuf, &logBuf
	if err := cmd.Start(); err != nil {
		return false, "start xray: " + err.Error()
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	if !waitTCP(socksAddr, 15*time.Second) {
		return false, "xray socks inbound never came up\n" + tail(logBuf.String(), 12)
	}

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return false, "socks dialer: " + err.Error()
	}
	hc := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{Dial: dialer.Dial, DisableKeepAlives: true}}
	start := time.Now()
	resp, err := hc.Get("http://10.77.0.1:8080/ping")
	if err != nil {
		return false, fmt.Sprintf("request failed after %s: %v\n%s", time.Since(start).Round(time.Millisecond), err, interesting(logBuf.String()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "AWG-LOOP-OK" {
		return false, fmt.Sprintf("unexpected body %q", body)
	}
	return true, fmt.Sprintf("body %q in %s", body, time.Since(start).Round(time.Millisecond))
}

func keypair() (priv, pub []byte) {
	priv = make([]byte, 32)
	rand.Read(priv)
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, _ = curve25519.X25519(priv, curve25519.Basepoint)
	return
}

func freeUDPPort() int {
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitTCP(addr string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// interesting keeps only the xray log lines that explain a handshake failure.
func interesting(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "unknown type") || strings.Contains(ll, "handshake") ||
			strings.Contains(ll, "error") || strings.Contains(ll, "panic") || strings.Contains(ll, "failed") {
			out = append(out, l)
		}
	}
	if len(out) > 10 {
		out = out[len(out)-10:]
	}
	if len(out) == 0 {
		return tail(s, 8)
	}
	return strings.Join(out, "\n")
}

func indent(s string) string {
	return "      " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n      ")
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
