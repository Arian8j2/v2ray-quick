package link

import (
	"errors"
	"fmt"
	"strings"
)

type Link interface {
	link()
}

func Parse(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("config link is empty")
	}

	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return ParseVLESS(raw)
	case strings.HasPrefix(lower, "vmess://"):
		return ParseVMess(raw)
	default:
		scheme, _, found := strings.Cut(raw, "://")
		if !found {
			return nil, fmt.Errorf("unsupported config link %q: only vless:// and vmess:// are implemented", raw)
		}
		return nil, fmt.Errorf("unsupported scheme %q: only vless:// and vmess:// are implemented", scheme)
	}
}
