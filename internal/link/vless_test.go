package link

import "testing"

func TestParseVLESSWebSocketNoTLS(t *testing.T) {
	parsed, err := ParseVLESS("vless://ecb3a720-3d05-403e-a834-feb735184173@example.com:2095?encryption=none&host=cdn.example.net&path=%2Fapp.js%2Fstreamplay%2Flive&security=none&type=ws#example-ws-no-tls")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if parsed.UUID != "ecb3a720-3d05-403e-a834-feb735184173" {
		t.Fatalf("UUID = %q", parsed.UUID)
	}
	if parsed.Server != "example.com" {
		t.Fatalf("Server = %q", parsed.Server)
	}
	if parsed.Port != 2095 {
		t.Fatalf("Port = %d", parsed.Port)
	}
	if parsed.Name != "example-ws-no-tls" {
		t.Fatalf("Name = %q", parsed.Name)
	}
	if parsed.Encryption != "none" {
		t.Fatalf("Encryption = %q", parsed.Encryption)
	}
	if parsed.Security.Type != "none" {
		t.Fatalf("Security.Type = %q", parsed.Security.Type)
	}
	if parsed.Security.Insecure {
		t.Fatalf("Security.Insecure = true")
	}
	if parsed.Transport.Type != "ws" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
	if parsed.Transport.Path != "/app.js/streamplay/live" {
		t.Fatalf("Transport.Path = %q", parsed.Transport.Path)
	}
	if parsed.Transport.Host != "cdn.example.net" {
		t.Fatalf("Transport.Host = %q", parsed.Transport.Host)
	}
}

func TestParseVLESSWebSocketDefaults(t *testing.T) {
	parsed, err := ParseVLESS("vless://1061a8a5-9368-41d2-b6e8-a07a9f7d81ba@example.org:80?encryption=none&type=ws&path=%2F&host=example.org#example-ws-defaults")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if parsed.UUID != "1061a8a5-9368-41d2-b6e8-a07a9f7d81ba" {
		t.Fatalf("UUID = %q", parsed.UUID)
	}
	if parsed.Server != "example.org" {
		t.Fatalf("Server = %q", parsed.Server)
	}
	if parsed.Port != 80 {
		t.Fatalf("Port = %d", parsed.Port)
	}
	if parsed.Name != "example-ws-defaults" {
		t.Fatalf("Name = %q", parsed.Name)
	}
	if parsed.Security.Type != "none" {
		t.Fatalf("Security.Type = %q", parsed.Security.Type)
	}
	if parsed.Transport.Type != "ws" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
	if parsed.Transport.Path != "/" {
		t.Fatalf("Transport.Path = %q", parsed.Transport.Path)
	}
	if parsed.Transport.Host != "example.org" {
		t.Fatalf("Transport.Host = %q", parsed.Transport.Host)
	}
}

func TestParseVLESSTLSWebSocket(t *testing.T) {
	parsed, err := ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@192.0.2.1:2096?path=%2F&security=tls&encryption=none&insecure=1&host=ws.example.net&type=ws&allowInsecure=1&sni=tls.example.net#example-tls-ws")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if parsed.UUID != "6202b230-417c-4d8e-b624-0f71afa9c75d" {
		t.Fatalf("UUID = %q", parsed.UUID)
	}
	if parsed.Server != "192.0.2.1" {
		t.Fatalf("Server = %q", parsed.Server)
	}
	if parsed.Port != 2096 {
		t.Fatalf("Port = %d", parsed.Port)
	}
	if parsed.Name != "example-tls-ws" {
		t.Fatalf("Name = %q", parsed.Name)
	}
	if parsed.Security.Type != "tls" {
		t.Fatalf("Security.Type = %q", parsed.Security.Type)
	}
	if parsed.Security.ServerName != "tls.example.net" {
		t.Fatalf("Security.ServerName = %q", parsed.Security.ServerName)
	}
	if !parsed.Security.Insecure {
		t.Fatalf("Security.Insecure = false")
	}
	if parsed.Transport.Type != "ws" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
	if parsed.Transport.Path != "/" {
		t.Fatalf("Transport.Path = %q", parsed.Transport.Path)
	}
	if parsed.Transport.Host != "ws.example.net" {
		t.Fatalf("Transport.Host = %q", parsed.Transport.Host)
	}
}

func TestParseVLESSReality(t *testing.T) {
	parsed, err := ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&spx=%2F&pqv=verify#example-reality")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if parsed.Flow != "xtls-rprx-vision" {
		t.Fatalf("Flow = %q", parsed.Flow)
	}
	if parsed.Security.Type != "reality" {
		t.Fatalf("Security.Type = %q", parsed.Security.Type)
	}
	if parsed.Security.ServerName != "www.example.com" {
		t.Fatalf("Security.ServerName = %q", parsed.Security.ServerName)
	}
	if parsed.Security.Fingerprint != "chrome" {
		t.Fatalf("Security.Fingerprint = %q", parsed.Security.Fingerprint)
	}
	if parsed.Security.PublicKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("Security.PublicKey = %q", parsed.Security.PublicKey)
	}
	if parsed.Security.ShortID != "0123456789abcdef" {
		t.Fatalf("Security.ShortID = %q", parsed.Security.ShortID)
	}
	if parsed.Security.SpiderX != "/" {
		t.Fatalf("Security.SpiderX = %q", parsed.Security.SpiderX)
	}
	if parsed.Security.MLDSA65Verify != "verify" {
		t.Fatalf("Security.MLDSA65Verify = %q", parsed.Security.MLDSA65Verify)
	}
}

func TestParseVLESSSupportedQueryFields(t *testing.T) {
	parsed, err := ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=tcp&headerType=http&host=front.example.com&path=%2Fa%2C%2Fb&sni=tls.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&ech=ech-value&pcs=abc&allow_insecure=1#example")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if !parsed.Security.Insecure {
		t.Fatalf("Security.Insecure = false")
	}
	if parsed.Security.ALPN != "h2,http/1.1" {
		t.Fatalf("Security.ALPN = %q", parsed.Security.ALPN)
	}
	if parsed.Security.ECH != "ech-value" {
		t.Fatalf("Security.ECH = %q", parsed.Security.ECH)
	}
	if parsed.Security.PinnedCA256 != "abc" {
		t.Fatalf("Security.PinnedCA256 = %q", parsed.Security.PinnedCA256)
	}
	if parsed.Transport.HeaderType != "http" {
		t.Fatalf("Transport.HeaderType = %q", parsed.Transport.HeaderType)
	}
	if parsed.Transport.Host != "front.example.com" {
		t.Fatalf("Transport.Host = %q", parsed.Transport.Host)
	}
	if parsed.Transport.Path != "/a,/b" {
		t.Fatalf("Transport.Path = %q", parsed.Transport.Path)
	}
}

func TestParseVLESSDefaults(t *testing.T) {
	parsed, err := ParseVLESS("vless://ecb3a720-3d05-403e-a834-feb735184173@example.com:443")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}

	if parsed.Encryption != "none" {
		t.Fatalf("Encryption = %q", parsed.Encryption)
	}
	if parsed.Security.Type != "none" {
		t.Fatalf("Security.Type = %q", parsed.Security.Type)
	}
	if parsed.Transport.Type != "tcp" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
}

func TestParseVLESSErrors(t *testing.T) {
	tests := []string{
		"",
		"vmess://example.com",
		"vless://example.com:443",
		"vless://ecb3a720-3d05-403e-a834-feb735184173@:443",
		"vless://ecb3a720-3d05-403e-a834-feb735184173@example.com",
		"vless://ecb3a720-3d05-403e-a834-feb735184173@example.com:0",
		"vless://ecb3a720-3d05-403e-a834-feb735184173@example.com:999999",
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			if _, err := ParseVLESS(test); err == nil {
				t.Fatalf("ParseVLESS() error = nil")
			}
		})
	}
}
