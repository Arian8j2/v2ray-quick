package quick

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"v2ray-quick/internal/link"
)

func LoadLink(path string) (link.Link, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "vless://") && !strings.HasPrefix(strings.ToLower(line), "vmess://") {
			return nil, fmt.Errorf("unsupported config link %q: only vless:// and vmess:// are implemented", line)
		}
		return link.Parse(line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return nil, errors.New("config file does not contain a vless:// or vmess:// link")
}

func LoadVLESS(path string) (*link.VLESS, error) {
	proxy, err := LoadLink(path)
	if err != nil {
		return nil, err
	}
	vless, ok := proxy.(*link.VLESS)
	if !ok {
		return nil, fmt.Errorf("config file contains %T, not a vless link", proxy)
	}
	return vless, nil
}
