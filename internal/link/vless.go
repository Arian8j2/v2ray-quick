package link

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type VLESS struct {
	Name       string
	UUID       string
	Server     string
	Port       uint16
	Encryption string
	Flow       string
	Security   Security
	Transport  Transport
}

type Security struct {
	Type          string
	ServerName    string
	Insecure      bool
	Fingerprint   string
	ALPN          string
	ECH           string
	PinnedCA256   string
	PublicKey     string
	ShortID       string
	SpiderX       string
	MLDSA65Verify string
}

type Transport struct {
	Type       string
	Path       string
	Host       string
	HeaderType string
}

func ParseVLESS(raw string) (*VLESS, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("vless link is empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse vless link: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	uuid := u.User.Username()
	if uuid == "" {
		return nil, errors.New("vless link is missing uuid")
	}

	server := u.Hostname()
	if server == "" {
		return nil, errors.New("vless link is missing server")
	}

	portRaw := u.Port()
	if portRaw == "" {
		return nil, errors.New("vless link is missing port")
	}
	port, err := parsePort(portRaw)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	encryption := valueOrDefault(query.Get("encryption"), "none")
	transportType := valueOrDefault(query.Get("type"), "tcp")
	securityType := valueOrDefault(query.Get("security"), "none")

	return &VLESS{
		Name:       u.Fragment,
		UUID:       uuid,
		Server:     server,
		Port:       port,
		Encryption: encryption,
		Flow:       query.Get("flow"),
		Security: Security{
			Type:          securityType,
			ServerName:    query.Get("sni"),
			Insecure:      isTruthy(query.Get("insecure")) || isTruthy(query.Get("allowInsecure")) || isTruthy(query.Get("allow_insecure")),
			Fingerprint:   query.Get("fp"),
			ALPN:          query.Get("alpn"),
			ECH:           query.Get("ech"),
			PinnedCA256:   query.Get("pcs"),
			PublicKey:     query.Get("pbk"),
			ShortID:       query.Get("sid"),
			SpiderX:       query.Get("spx"),
			MLDSA65Verify: query.Get("pqv"),
		},
		Transport: Transport{
			Type:       transportType,
			Path:       query.Get("path"),
			Host:       query.Get("host"),
			HeaderType: query.Get("headerType"),
		},
	}, nil
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid vless port %q", raw)
	}
	return uint16(port), nil
}

func valueOrDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func isTruthy(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
