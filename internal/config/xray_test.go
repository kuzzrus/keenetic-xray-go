package config

import (
	"encoding/json"
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
}
