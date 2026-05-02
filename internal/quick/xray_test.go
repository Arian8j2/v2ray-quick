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

func TestBuildConfigParsesV2rayNGTransportFields(t *testing.T) {
	tests := []string{
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=none&encryption=none&type=tcp&headerType=http&host=front.example.com&path=%2Fa%2C%2Fb#tcp-http",
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=none&encryption=none&type=kcp&headerType=none&seed=kcp-seed&mtu=1350&tti=20#kcp",
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=httpupgrade&host=up.example.com&path=%2Fup&sni=tls.example.com&fp=chrome&alpn=h2#httpupgrade",
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=xhttp&host=x.example.com&path=%2Fx&mode=auto&extra=%7B%22noSSEHeader%22%3Atrue%7D&sni=tls.example.com&fp=chrome#xhttp",
		"vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&encryption=none&type=grpc&mode=multi&serviceName=svc&authority=grpc.example.com&sni=tls.example.com&fp=chrome#grpc",
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
