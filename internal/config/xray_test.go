package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateXrayConfig_TCPNone(t *testing.T) {
	p := validProfile() // tcp / none
	data, err := GenerateXrayConfig(XrayConfigOptions{
		SOCKSPort: 1080,
		HTTPPort:  1081,
		Outbound:  p,
	})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("generated config is not valid JSON: %v\n%s", err, data)
	}

	inbounds, ok := decoded["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds (socks+http), got %#v", decoded["inbounds"])
	}

	outbounds, ok := decoded["outbounds"].([]any)
	if !ok || len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds (proxy, direct, block), got %#v", decoded["outbounds"])
	}
	first := outbounds[0].(map[string]any)
	if first["tag"] != "proxy" || first["protocol"] != "vless" {
		t.Errorf("first outbound = %#v, want tag=proxy protocol=vless", first)
	}

	settings := first["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)[0].(map[string]any)
	if vnext["address"] != p.Address {
		t.Errorf("vnext address = %v, want %v", vnext["address"], p.Address)
	}
	users := vnext["users"].([]any)[0].(map[string]any)
	if users["id"] != p.UUID {
		t.Errorf("user id = %v, want %v", users["id"], p.UUID)
	}

	// routing must be absent: no geodata, first outbound is the implicit default.
	if _, present := decoded["routing"]; present {
		t.Errorf("expected no routing block, got %#v", decoded["routing"])
	}
}

func TestGenerateXrayConfig_WSTLS(t *testing.T) {
	p := validProfile()
	p.Network = "ws"
	p.Security = "tls"
	p.SNI = "cdn.example.com"
	p.Path = "/ws"
	p.Host = "cdn.example.com"

	data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	outbound := decoded["outbounds"].([]any)[0].(map[string]any)
	stream := outbound["streamSettings"].(map[string]any)

	if stream["network"] != "ws" || stream["security"] != "tls" {
		t.Errorf("stream = %#v, want network=ws security=tls", stream)
	}
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "cdn.example.com" {
		t.Errorf("tlsSettings.serverName = %v, want cdn.example.com", tlsSettings["serverName"])
	}
	wsSettings := stream["wsSettings"].(map[string]any)
	if wsSettings["path"] != "/ws" {
		t.Errorf("wsSettings.path = %v, want /ws", wsSettings["path"])
	}
}

func TestGenerateXrayConfig_XHTTPTLS(t *testing.T) {
	p := validProfile()
	p.Network = "xhttp"
	p.Security = "tls"
	p.SNI = "cdn.example.com"
	p.Path = "/xhttp"
	p.Host = "cdn.example.com"
	p.Mode = "stream-up"

	data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	outbound := decoded["outbounds"].([]any)[0].(map[string]any)
	stream := outbound["streamSettings"].(map[string]any)

	if stream["network"] != "xhttp" || stream["security"] != "tls" {
		t.Errorf("stream = %#v, want network=xhttp security=tls", stream)
	}
	xhttpSettings := stream["xhttpSettings"].(map[string]any)
	if xhttpSettings["path"] != "/xhttp" {
		t.Errorf("xhttpSettings.path = %v, want /xhttp", xhttpSettings["path"])
	}
	if xhttpSettings["host"] != "cdn.example.com" {
		t.Errorf("xhttpSettings.host = %v, want cdn.example.com", xhttpSettings["host"])
	}
	if xhttpSettings["mode"] != "stream-up" {
		t.Errorf("xhttpSettings.mode = %v, want stream-up", xhttpSettings["mode"])
	}
}

func TestGenerateXrayConfig_XHTTPExtraAndModeOverride(t *testing.T) {
	p := validProfile()
	p.Network = "xhttp"
	p.Security = "reality"
	p.SNI = "cdn.example.com"
	p.PublicKey = "pk"
	p.ShortID = "sid"
	p.Path = "/xhttp"
	p.Mode = "auto"
	p.XHTTPExtra = json.RawMessage(`{"xmux":{"maxConcurrency":"16-32","cMaxReuseTimes":"64-128"},"scMaxEachPostBytes":1000000,"xPaddingBytes":"100-1000"}`)

	data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p, XHTTPMode: "stream-up"})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	xs := decoded["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["xhttpSettings"].(map[string]any)

	if xs["path"] != "/xhttp" {
		t.Errorf("path = %v", xs["path"])
	}
	if xs["mode"] != "stream-up" {
		t.Errorf("mode = %v, want the XHTTPMode override to beat the profile's auto", xs["mode"])
	}
	if xs["scMaxEachPostBytes"] != float64(1000000) || xs["xPaddingBytes"] != "100-1000" {
		t.Errorf("extra tuning not merged: %#v", xs)
	}
	xmux, ok := xs["xmux"].(map[string]any)
	if !ok || xmux["maxConcurrency"] != "16-32" || xmux["cMaxReuseTimes"] != "64-128" {
		t.Errorf("xmux not merged: %#v", xs["xmux"])
	}
}

func TestGenerateXrayConfig_GRPCReality(t *testing.T) {
	p := validProfile()
	p.Network = "grpc"
	p.Security = "reality"
	p.PublicKey = "PUBKEY"
	p.ShortID = "SHORTID"
	p.SNI = "www.example.com"
	p.ServiceName = "grpcsvc"

	data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	outbound := decoded["outbounds"].([]any)[0].(map[string]any)
	stream := outbound["streamSettings"].(map[string]any)

	if stream["security"] != "reality" {
		t.Errorf("security = %v, want reality", stream["security"])
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["publicKey"] != "PUBKEY" || reality["shortId"] != "SHORTID" {
		t.Errorf("realitySettings = %#v", reality)
	}
	if reality["serverName"] != "www.example.com" {
		t.Errorf("realitySettings.serverName = %v, want www.example.com", reality["serverName"])
	}
	grpcSettings := stream["grpcSettings"].(map[string]any)
	if grpcSettings["serviceName"] != "grpcsvc" {
		t.Errorf("grpcSettings.serviceName = %v, want grpcsvc", grpcSettings["serviceName"])
	}
}

func TestGenerateXrayConfig_HTTP2(t *testing.T) {
	// A profile stored as "h2" (an older share-link alias) must still
	// produce an "http" transport -- the name Xray-core expects -- with
	// httpSettings, not a config Xray rejects as an unknown network.
	for _, network := range []string{"h2", "http"} {
		t.Run(network, func(t *testing.T) {
			p := validProfile()
			p.Network = network
			p.Security = "tls"
			p.SNI = "cdn.example.com"
			p.Path = "/h2"
			p.Host = "cdn.example.com"

			data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
			if err != nil {
				t.Fatalf("GenerateXrayConfig: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			stream := decoded["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)

			if stream["network"] != "http" {
				t.Errorf("network = %v, want http", stream["network"])
			}
			httpSettings, ok := stream["httpSettings"].(map[string]any)
			if !ok {
				t.Fatalf("httpSettings missing: %#v", stream)
			}
			if httpSettings["path"] != "/h2" {
				t.Errorf("httpSettings.path = %v, want /h2", httpSettings["path"])
			}
			if hosts, ok := httpSettings["host"].([]any); !ok || len(hosts) != 1 || hosts[0] != "cdn.example.com" {
				t.Errorf("httpSettings.host = %#v, want [cdn.example.com]", httpSettings["host"])
			}
		})
	}
}

func TestGenerateXrayConfig_ProductionAndPretestDoNotDrift(t *testing.T) {
	primary := validProfile()
	primary.Remark = "primary"

	prod, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, HTTPPort: 1081, Outbound: primary})
	if err != nil {
		t.Fatalf("prod config: %v", err)
	}
	pretest, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 11080, Outbound: primary})
	if err != nil {
		t.Fatalf("pretest config: %v", err)
	}

	var prodDecoded, pretestDecoded map[string]any
	if err := json.Unmarshal(prod, &prodDecoded); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pretest, &pretestDecoded); err != nil {
		t.Fatal(err)
	}

	prodOutbound := prodDecoded["outbounds"].([]any)[0]
	pretestOutbound := pretestDecoded["outbounds"].([]any)[0]
	prodJSON, _ := json.Marshal(prodOutbound)
	pretestJSON, _ := json.Marshal(pretestOutbound)
	if string(prodJSON) != string(pretestJSON) {
		t.Errorf("production and pretest outbounds diverged:\nprod:    %s\npretest: %s", prodJSON, pretestJSON)
	}

	prodInbounds := prodDecoded["inbounds"].([]any)
	pretestInbounds := pretestDecoded["inbounds"].([]any)
	if len(prodInbounds) != 2 || len(pretestInbounds) != 1 {
		t.Errorf("expected prod to have 2 inbounds and pretest 1, got %d and %d", len(prodInbounds), len(pretestInbounds))
	}
}

func TestGenerateXrayConfig_ListenHost(t *testing.T) {
	decode := func(opts XrayConfigOptions) []map[string]any {
		data, err := GenerateXrayConfig(opts)
		if err != nil {
			t.Fatalf("GenerateXrayConfig: %v", err)
		}
		var cfg struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return cfg.Inbounds
	}

	for _, in := range decode(XrayConfigOptions{SOCKSPort: 1080, HTTPPort: 1081, Outbound: validProfile()}) {
		if in["listen"] != "127.0.0.1" {
			t.Errorf("default listen = %v, want 127.0.0.1", in["listen"])
		}
	}
	for _, in := range decode(XrayConfigOptions{SOCKSPort: 1080, HTTPPort: 1081, ListenHost: "0.0.0.0", Outbound: validProfile()}) {
		if in["listen"] != "0.0.0.0" {
			t.Errorf("listen = %v, want 0.0.0.0", in["listen"])
		}
	}
}

func TestGenerateXrayConfig_WGInbound(t *testing.T) {
	priv, pub, _ := GenerateWGKeypair()
	_, keeneticPub, _ := GenerateWGKeypair()
	psk, _ := GenerateWGPSK()

	base := XrayConfigOptions{SOCKSPort: 1080, HTTPPort: 1081, Outbound: validProfile()}

	// No WG option -> two inbounds, no wireguard.
	data, err := GenerateXrayConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := inboundProtocols(t, data); len(got) != 2 || contains(got, "wireguard") {
		t.Fatalf("without WG: protocols = %v", got)
	}

	// With WG option -> a third inbound.
	withWG := base
	withWG.WG = &WGInboundOptions{
		ListenHost: "0.0.0.0", Port: DefaultWGPort, SecretKey: priv, MTU: 1280,
		PeerPublicKey: keeneticPub, PeerPSK: psk,
	}
	data, err = GenerateXrayConfig(withWG)
	if err != nil {
		t.Fatalf("with WG: %v", err)
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 3 {
		t.Fatalf("want 3 inbounds, got %d", len(cfg.Inbounds))
	}
	wg := cfg.Inbounds[2]
	if wg["protocol"] != "wireguard" || wg["tag"] != "wg-in" || wg["listen"] != "0.0.0.0" {
		t.Fatalf("wg inbound shell = %#v", wg)
	}
	s := wg["settings"].(map[string]any)
	if s["secretKey"] != priv || s["kernelMode"] != false || s["mtu"].(float64) != 1280 {
		t.Errorf("wg settings = %#v", s)
	}
	peer := s["peers"].([]any)[0].(map[string]any)
	if peer["publicKey"] != keeneticPub || peer["preSharedKey"] != psk {
		t.Errorf("wg peer = %#v", peer)
	}
	if ips := peer["allowedIPs"].([]any); len(ips) != 1 || ips[0] != "0.0.0.0/0" {
		t.Errorf("allowedIPs = %#v", peer["allowedIPs"])
	}
	_ = pub

	// PSK omitted when empty; bad key rejected.
	withWG.WG.PeerPSK = ""
	if data, err = GenerateXrayConfig(withWG); err != nil {
		t.Fatal(err)
	} else {
		var c2 struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		_ = json.Unmarshal(data, &c2)
		p := c2.Inbounds[2]["settings"].(map[string]any)["peers"].([]any)[0].(map[string]any)
		if _, ok := p["preSharedKey"]; ok {
			t.Error("preSharedKey present despite empty PSK")
		}
	}
	withWG.WG.SecretKey = "truncated"
	if _, err := GenerateXrayConfig(withWG); err == nil {
		t.Error("expected error for a bad WG secret key")
	}
}

func inboundProtocols(t *testing.T, data []byte) []string {
	t.Helper()
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, in := range cfg.Inbounds {
		out = append(out, in["protocol"].(string))
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestGenerateXrayConfig_Errors(t *testing.T) {
	t.Run("no ports", func(t *testing.T) {
		_, err := GenerateXrayConfig(XrayConfigOptions{Outbound: validProfile()})
		if err == nil {
			t.Error("expected error when no inbound port is set")
		}
	})
	t.Run("invalid profile", func(t *testing.T) {
		p := validProfile()
		p.UUID = ""
		_, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
		if err == nil {
			t.Error("expected error for invalid outbound profile")
		}
	})
	t.Run("grpc with no serviceName or path", func(t *testing.T) {
		p := validProfile()
		p.Network = "grpc"
		p.ServiceName = ""
		p.Path = ""
		_, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
		if err == nil {
			t.Error("expected error for grpc network with no serviceName/path -- an empty grpcSettings.serviceName silently generates a non-functional tunnel")
		}
	})
	t.Run("naive profile without a running sidecar", func(t *testing.T) {
		// Profile.Validate() accepts a naive profile (it has no
		// UUID/Network/Security to check), so a missing SidecarSOCKS must
		// be rejected here with a clear reason -- not fall through to a
		// vless outbound built from empty fields, which would instead
		// fail deeper with a confusing "unsupported security \"\"".
		p := Profile{Protocol: "naive", Address: "n.example.com", Port: 443, User: "u", Password: "p"}
		_, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p})
		if err == nil {
			t.Fatal("expected an error -- no SidecarSOCKS was set")
		}
		if !strings.Contains(err.Error(), "naive") {
			t.Errorf("error = %q, want it to name naive as the reason", err.Error())
		}
	})
}

func TestGenerateXrayConfig_NaiveSidecarOutbound(t *testing.T) {
	p := Profile{Protocol: "naive", Remark: "Naive", Address: "n.example.com", Port: 8443, User: "alice", Password: "s3cret"}
	data, err := GenerateXrayConfig(XrayConfigOptions{SOCKSPort: 1080, Outbound: p, SidecarSOCKS: 21090})
	if err != nil {
		t.Fatalf("GenerateXrayConfig: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	outbound := decoded["outbounds"].([]any)[0].(map[string]any)
	if outbound["tag"] != "proxy" || outbound["protocol"] != "socks" {
		t.Fatalf("outbound = %#v, want tag=proxy protocol=socks", outbound)
	}
	// Must not leak the naive server's own address/credentials into the
	// xray config -- those live only in the sidecar's own argv.
	settings := outbound["settings"].(map[string]any)
	server := settings["servers"].([]any)[0].(map[string]any)
	if server["address"] != "127.0.0.1" || server["port"] != float64(21090) {
		t.Errorf("socks server = %#v, want 127.0.0.1:21090", server)
	}
	if strings.Contains(string(data), "n.example.com") || strings.Contains(string(data), "s3cret") {
		t.Errorf("naive server address/credentials leaked into the xray config: %s", data)
	}
}
