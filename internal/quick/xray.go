package quick

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"v2ray-quick/internal/link"
)

type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   xrayRouting    `json:"routing"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayInbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings xrayTunSettings `json:"settings"`
}

type xrayTunSettings struct {
	Name string `json:"name"`
	MTU  uint32 `json:"MTU"`
}

type xrayOutbound struct {
	Tag            string              `json:"tag"`
	Protocol       string              `json:"protocol"`
	Settings       any                 `json:"settings,omitempty"`
	StreamSettings *xrayStreamSettings `json:"streamSettings,omitempty"`
}

type xrayVLESSSettings struct {
	Vnext []xrayVLESSVNext `json:"vnext"`
}

type xrayVLESSVNext struct {
	Address string          `json:"address"`
	Port    uint16          `json:"port"`
	Users   []xrayVLESSUser `json:"users"`
}

type xrayVLESSUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type xrayStreamSettings struct {
	Network         string               `json:"network"`
	Security        string               `json:"security,omitempty"`
	TLSSettings     *xrayTLSSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *xrayRealitySettings `json:"realitySettings,omitempty"`
	TCPSettings     *xrayTCPSettings     `json:"tcpSettings,omitempty"`
	WSSettings      *xrayWSSettings      `json:"wsSettings,omitempty"`
}

type xrayTLSSettings struct {
	ServerName           string   `json:"serverName,omitempty"`
	AllowInsecure        bool     `json:"allowInsecure,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	ALPN                 []string `json:"alpn,omitempty"`
	ECHConfigList        string   `json:"echConfigList,omitempty"`
	PinnedPeerCertSHA256 string   `json:"pinnedPeerCertSha256,omitempty"`
}

type xrayRealitySettings struct {
	ServerName    string `json:"serverName,omitempty"`
	Fingerprint   string `json:"fingerprint"`
	PublicKey     string `json:"publicKey"`
	ShortID       string `json:"shortId,omitempty"`
	SpiderX       string `json:"spiderX,omitempty"`
	MLDSA65Verify string `json:"mldsa65Verify,omitempty"`
}

type xrayTCPSettings struct {
	Header xrayTCPHeader `json:"header"`
}

type xrayTCPHeader struct {
	Type    string           `json:"type"`
	Request *xrayHTTPRequest `json:"request,omitempty"`
}

type xrayHTTPRequest struct {
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type xrayWSSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type xrayRouting struct {
	DomainStrategy string `json:"domainStrategy"`
}

func BuildConfig(vless *link.VLESS, interfaceName string) (xrayConfig, error) {
	outbound, err := buildVLESSOutbound(vless)
	if err != nil {
		return xrayConfig{}, err
	}

	return xrayConfig{
		Log: xrayLog{
			LogLevel: "info",
		},
		Inbounds: []xrayInbound{
			{
				Tag:      "tun-in",
				Protocol: "tun",
				Settings: xrayTunSettings{
					Name: interfaceName,
					MTU:  1500,
				},
			},
		},
		Outbounds: []xrayOutbound{
			outbound,
			{
				Tag:      "direct",
				Protocol: "freedom",
			},
		},
		Routing: xrayRouting{
			DomainStrategy: "AsIs",
		},
	}, nil
}

func buildVLESSOutbound(vless *link.VLESS) (xrayOutbound, error) {
	if !strings.EqualFold(vless.Encryption, "none") {
		return xrayOutbound{}, fmt.Errorf("unsupported vless encryption %q", vless.Encryption)
	}

	streamSettings := &xrayStreamSettings{}
	switch strings.ToLower(vless.Security.Type) {
	case "", "none":
		streamSettings.Security = "none"
	case "tls":
		streamSettings.Security = "tls"
		streamSettings.TLSSettings = &xrayTLSSettings{
			ServerName:           vless.Security.ServerName,
			AllowInsecure:        vless.Security.Insecure,
			Fingerprint:          vless.Security.Fingerprint,
			ALPN:                 splitComma(vless.Security.ALPN),
			ECHConfigList:        vless.Security.ECH,
			PinnedPeerCertSHA256: vless.Security.PinnedCA256,
		}
	case "reality":
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &xrayRealitySettings{
			ServerName:    vless.Security.ServerName,
			Fingerprint:   vless.Security.Fingerprint,
			PublicKey:     vless.Security.PublicKey,
			ShortID:       vless.Security.ShortID,
			SpiderX:       vless.Security.SpiderX,
			MLDSA65Verify: vless.Security.MLDSA65Verify,
		}
	default:
		return xrayOutbound{}, fmt.Errorf("unsupported vless security %q", vless.Security.Type)
	}

	switch strings.ToLower(vless.Transport.Type) {
	case "", "tcp":
		streamSettings.Network = "tcp"
		streamSettings.TCPSettings = buildTCPSettings(vless.Transport)
	case "ws":
		streamSettings.Network = "ws"
		streamSettings.WSSettings = &xrayWSSettings{
			Path: vless.Transport.Path,
			Host: vless.Transport.Host,
		}
	default:
		return xrayOutbound{}, fmt.Errorf("unsupported vless transport %q", vless.Transport.Type)
	}

	return xrayOutbound{
		Tag:      "proxy",
		Protocol: "vless",
		Settings: xrayVLESSSettings{
			Vnext: []xrayVLESSVNext{
				{
					Address: vless.Server,
					Port:    vless.Port,
					Users: []xrayVLESSUser{
						{
							ID:         vless.UUID,
							Encryption: vless.Encryption,
							Flow:       vless.Flow,
						},
					},
				},
			},
		},
		StreamSettings: streamSettings,
	}, nil
}

func buildTCPSettings(transport link.Transport) *xrayTCPSettings {
	headerType := transport.HeaderType
	if headerType == "" {
		headerType = "none"
	}
	settings := &xrayTCPSettings{
		Header: xrayTCPHeader{Type: headerType},
	}
	if !strings.EqualFold(headerType, "http") {
		return settings
	}
	request := &xrayHTTPRequest{}
	if paths := splitComma(transport.Path); len(paths) > 0 {
		request.Path = paths
	}
	if hosts := splitComma(transport.Host); len(hosts) > 0 {
		request.Headers = map[string][]string{"Host": hosts}
	}
	settings.Header.Request = request
	return settings
}

func splitComma(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func writeXrayConfig(writer io.Writer, config xrayConfig) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("write xray config: %w", err)
	}
	return nil
}

func startXray(ctx context.Context, config xrayConfig) (*core.Instance, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)
	var buffer bytes.Buffer
	if err := writeXrayConfig(&buffer, config); err != nil {
		cancel()
		return nil, nil, err
	}
	pbConfig, err := serial.LoadJSONConfig(&buffer)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("parse xray config: %w", err)
	}

	instance, err := core.NewWithContext(ctx, pbConfig)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("create xray service: %w", err)
	}
	if err := instance.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("start xray service: %w", err)
	}

	return instance, cancel, nil
}

func closeXray(instance *core.Instance) error {
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()

	done := make(chan error, 1)
	go func() {
		done <- instance.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("close xray service: %w", err)
		}
		return nil
	case <-closeCtx.Done():
		return errors.New("timed out closing xray service")
	}
}

func assignTunAddress(interfaceName string, address string) error {
	if err := validateTunAddress(address); err != nil {
		return err
	}

	cmd := exec.Command("ip", "address", "add", address, "dev", interfaceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	printCommand(cmd.Args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("assign address %s to interface %s: %w", address, interfaceName, err)
	}
	return nil
}

func validateTunAddress(address string) error {
	if _, err := netip.ParsePrefix(address); err != nil {
		return fmt.Errorf("invalid tun address %q: %w", address, err)
	}
	return nil
}
