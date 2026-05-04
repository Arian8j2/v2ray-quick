package link

import "testing"

const sampleVMess = "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImhvc3QiOiJ3cy5leGFtcGxlLm5ldCIsImlkIjoiNjIwMmIyMzAtNDE3Yy00ZDhlLWI2MjQtMGY3MWFmYTljNzVkIiwibmV0Ijoid3MiLCJwYXRoIjoiL2FkZmZyMjFhc2QzMTIiLCJwb3J0Ijo4MCwicHMiOiJleGFtcGxlLXZtZXNzLXdzIiwic2N5IjoiYXV0byIsInRscyI6Im5vbmUiLCJ0eXBlIjoibm9uZSIsInYiOiIyIn0="

func TestParseVMessWebSocketNoTLS(t *testing.T) {
	parsed, err := ParseVMess(sampleVMess)
	if err != nil {
		t.Fatalf("ParseVMess() error = %v", err)
	}

	if parsed.UUID != "6202b230-417c-4d8e-b624-0f71afa9c75d" {
		t.Fatalf("UUID = %q", parsed.UUID)
	}
	if parsed.Server != "example.com" {
		t.Fatalf("Server = %q", parsed.Server)
	}
	if parsed.Port != 80 {
		t.Fatalf("Port = %d", parsed.Port)
	}
	if parsed.Name != "example-vmess-ws" {
		t.Fatalf("Name = %q", parsed.Name)
	}
	if parsed.Security != "auto" {
		t.Fatalf("Security = %q", parsed.Security)
	}
	if parsed.TLS.Type != "none" {
		t.Fatalf("TLS.Type = %q", parsed.TLS.Type)
	}
	if parsed.Transport.Type != "ws" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
	if parsed.Transport.Path != "/adffr21asd312" {
		t.Fatalf("Transport.Path = %q", parsed.Transport.Path)
	}
	if parsed.Transport.Host != "ws.example.net" {
		t.Fatalf("Transport.Host = %q", parsed.Transport.Host)
	}
	if parsed.Transport.HeaderType != "none" {
		t.Fatalf("Transport.HeaderType = %q", parsed.Transport.HeaderType)
	}
}

func TestParseDispatchesVMess(t *testing.T) {
	parsed, err := Parse(sampleVMess)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, ok := parsed.(*VMess); !ok {
		t.Fatalf("Parse() type = %T", parsed)
	}
}

func TestParseVMessDefaults(t *testing.T) {
	parsed, err := ParseVMess("vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImlkIjoiYzM4Njg3MWItN2Q1MC00ZDdmLWFiMGItZDY0ZTRiNWEzMWZkIiwicG9ydCI6IjQ0MyJ9")
	if err != nil {
		t.Fatalf("ParseVMess() error = %v", err)
	}

	if parsed.Security != "auto" {
		t.Fatalf("Security = %q", parsed.Security)
	}
	if parsed.TLS.Type != "none" {
		t.Fatalf("TLS.Type = %q", parsed.TLS.Type)
	}
	if parsed.Transport.Type != "tcp" {
		t.Fatalf("Transport.Type = %q", parsed.Transport.Type)
	}
}

func TestParseVMessErrors(t *testing.T) {
	tests := []string{
		"",
		"vless://example.com:443",
		"vmess://",
		"vmess://not-base64",
		"vmess://e30=",
		"vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImlkIjoiYzM4Njg3MWItN2Q1MC00ZDdmLWFiMGItZDY0ZTRiNWEzMWZkIn0=",
		"vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImlkIjoiYzM4Njg3MWItN2Q1MC00ZDdmLWFiMGItZDY0ZTRiNWEzMWZkIiwicG9ydCI6MH0=",
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			if _, err := ParseVMess(test); err == nil {
				t.Fatalf("ParseVMess() error = nil")
			}
		})
	}
}
