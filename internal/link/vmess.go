package link

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type VMess struct {
	Name      string
	UUID      string
	Server    string
	Port      uint16
	AlterID   int
	Security  string
	Transport Transport
	TLS       Security
}

func (*VMess) link() {}

type vmessShare struct {
	Name        string          `json:"ps"`
	Server      string          `json:"add"`
	Port        json.RawMessage `json:"port"`
	UUID        string          `json:"id"`
	AlterID     json.RawMessage `json:"aid"`
	Security    string          `json:"scy"`
	Network     string          `json:"net"`
	HeaderType  string          `json:"type"`
	Host        string          `json:"host"`
	Path        string          `json:"path"`
	TLS         string          `json:"tls"`
	ServerName  string          `json:"sni"`
	Fingerprint string          `json:"fp"`
	ALPN        string          `json:"alpn"`
}

func ParseVMess(raw string) (*VMess, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("vmess link is empty")
	}
	if !strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return nil, fmt.Errorf("unsupported scheme %q", schemeOf(raw))
	}

	payload := strings.TrimSpace(raw[len("vmess://"):])
	if payload == "" {
		return nil, errors.New("vmess link is missing payload")
	}
	decoded, err := decodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("decode vmess link: %w", err)
	}

	var share vmessShare
	if err := json.Unmarshal(decoded, &share); err != nil {
		return nil, fmt.Errorf("parse vmess json: %w", err)
	}
	if share.UUID == "" {
		return nil, errors.New("vmess link is missing uuid")
	}
	if share.Server == "" {
		return nil, errors.New("vmess link is missing server")
	}
	port, err := parseRawPort(share.Port)
	if err != nil {
		return nil, err
	}
	alterID, err := parseOptionalRawInt(share.AlterID)
	if err != nil {
		return nil, fmt.Errorf("invalid vmess alter id: %w", err)
	}

	return &VMess{
		Name:     share.Name,
		UUID:     share.UUID,
		Server:   share.Server,
		Port:     port,
		AlterID:  alterID,
		Security: valueOrDefault(share.Security, "auto"),
		Transport: Transport{
			Type:       valueOrDefault(share.Network, "tcp"),
			Path:       share.Path,
			Host:       share.Host,
			HeaderType: share.HeaderType,
		},
		TLS: Security{
			Type:        valueOrDefault(share.TLS, "none"),
			ServerName:  share.ServerName,
			Fingerprint: share.Fingerprint,
			ALPN:        share.ALPN,
		},
	}, nil
}

func decodeBase64(payload string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(payload)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func parseRawPort(raw json.RawMessage) (uint16, error) {
	if len(raw) == 0 {
		return 0, errors.New("vmess link is missing port")
	}
	value, err := parseRawUint(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", string(raw))
	}
	return parsePort(strconv.FormatUint(value, 10))
}

func parseOptionalRawInt(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	value, err := parseRawUint(raw)
	if err != nil {
		return 0, err
	}
	maxInt := uint64(int(^uint(0) >> 1))
	if value > maxInt {
		return 0, fmt.Errorf("value %d overflows int", value)
	}
	return int(value), nil
}

func parseRawUint(raw json.RawMessage) (uint64, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strconv.ParseUint(text, 10, 64)
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	return 0, fmt.Errorf("unsupported value %q", string(raw))
}

func schemeOf(raw string) string {
	scheme, _, found := strings.Cut(raw, "://")
	if !found {
		return ""
	}
	return scheme
}
