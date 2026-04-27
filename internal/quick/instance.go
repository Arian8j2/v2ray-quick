package quick

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Instance struct {
	ConfigPath    string
	InterfaceName string
}

func NewInstance(configPath string) (Instance, error) {
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return Instance{}, fmt.Errorf("resolve config path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Instance{}, fmt.Errorf("resolve config path: %w", err)
	}
	configName := filepath.Base(canonical)
	if !strings.HasSuffix(configName, ".conf") {
		return Instance{}, fmt.Errorf("config filename must match .+\\.conf: %s", configName)
	}
	interfaceName := strings.TrimSuffix(configName, ".conf")
	if interfaceName == "" {
		return Instance{}, fmt.Errorf("config filename must match .+\\.conf: %s", configName)
	}
	if len(interfaceName) > 15 {
		return Instance{}, fmt.Errorf("tun interface name %q is too long: Linux interface names must be at most 15 bytes", interfaceName)
	}

	return Instance{
		ConfigPath:    canonical,
		InterfaceName: interfaceName,
	}, nil
}
