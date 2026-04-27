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

func LoadVLESS(path string) (*link.VLESS, error) {
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
		if !strings.HasPrefix(strings.ToLower(line), "vless://") {
			return nil, fmt.Errorf("unsupported config link %q: only vless:// is implemented", line)
		}
		return link.ParseVLESS(line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return nil, errors.New("config file does not contain a vless:// link")
}
