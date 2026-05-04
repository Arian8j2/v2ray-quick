package quick

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"

	"v2ray-quick/internal/link"
)

func TestBuildConfigParsesAsXrayJSON(t *testing.T) {
	parsed, err := link.ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=ws&host=ws.example.com&path=%2F&sni=tls.example.com&fp=chrome#example")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}
	config, err := BuildConfig(parsed, "example")
	if err != nil {
		t.Fatalf("BuildConfig() error = %v", err)
	}

	assertXrayConfigLoads(t, config)
}

func TestBuildConfigParsesRealityAsXrayJSON(t *testing.T) {
	parsed, err := link.ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&spx=%2F#example")
	if err != nil {
		t.Fatalf("ParseVLESS() error = %v", err)
	}
	config, err := BuildConfig(parsed, "example")
	if err != nil {
		t.Fatalf("BuildConfig() error = %v", err)
	}

	assertXrayConfigLoads(t, config)
}

func TestBuildConfigParsesSupportedTransports(t *testing.T) {
	tests := []string{
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=none&encryption=none&type=tcp&headerType=http&host=front.example.com&path=%2Fa%2C%2Fb#tcp-http",
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=ws&host=ws.example.com&path=%2F&sni=tls.example.com&fp=chrome#ws",
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			parsed, err := link.ParseVLESS(test)
			if err != nil {
				t.Fatalf("ParseVLESS() error = %v", err)
			}
			config, err := BuildConfig(parsed, "example")
			if err != nil {
				t.Fatalf("BuildConfig() error = %v", err)
			}
			assertXrayConfigLoads(t, config)
		})
	}
}

func TestBuildConfigRejectsUnsupportedTransports(t *testing.T) {
	tests := []string{"kcp", "httpupgrade", "xhttp", "grpc"}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			parsed, err := link.ParseVLESS("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=none&encryption=none&type=" + test + "#" + test)
			if err != nil {
				t.Fatalf("ParseVLESS() error = %v", err)
			}
			if _, err := BuildConfig(parsed, "example"); err == nil {
				t.Fatalf("BuildConfig() error = nil")
			}
		})
	}
}

func assertXrayConfigLoads(t *testing.T, config xrayConfig) {
	t.Helper()

	var buffer bytes.Buffer
	if err := writeXrayConfig(&buffer, config); err != nil {
		t.Fatalf("writeXrayConfig() error = %v", err)
	}
	if _, err := serial.LoadJSONConfig(&buffer); err != nil {
		t.Fatalf("LoadJSONConfig() error = %v", err)
	}
}
