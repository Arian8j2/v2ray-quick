package quick

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runForeground(instance Instance, address string) error {
	if interfaceExists(instance.InterfaceName) {
		return fmt.Errorf("interface %s already exists", instance.InterfaceName)
	}

	vless, err := LoadVLESS(instance.ConfigPath)
	if err != nil {
		return err
	}
	config, err := BuildConfig(vless, instance.InterfaceName)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	service, stopService, err := startXray(ctx, config)
	if err != nil {
		return err
	}
	defer stopService()

	if err := waitForInterface(ctx, instance.InterfaceName, 10*time.Second); err != nil {
		cancel()
		stopService()
		_ = closeXray(service)
		return err
	}
	if err := assignTunAddress(instance.InterfaceName, address); err != nil {
		cancel()
		stopService()
		_ = closeXray(service)
		return err
	}
	interfaceDeleted := make(chan struct{}, 1)
	go watchInterface(ctx, instance.InterfaceName, interfaceDeleted)

	interfaceWasDeleted := false
	select {
	case signal := <-signals:
		fmt.Fprintf(os.Stderr, "received %s, shutting down\n", signal)
	case <-interfaceDeleted:
		interfaceWasDeleted = true
		fmt.Fprintf(os.Stderr, "interface %s disappeared, shutting down\n", instance.InterfaceName)
	}

	cancel()
	stopService()
	err = closeXray(service)
	if interfaceWasDeleted {
		return nil
	}
	return err
}

func waitForInterface(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for interface %s", name)
		case <-ticker.C:
		}
	}
}

func watchInterface(ctx context.Context, name string, deleted chan<- struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	seen := false

	for {
		if _, err := net.InterfaceByName(name); err == nil {
			seen = true
		} else if seen {
			select {
			case deleted <- struct{}{}:
			default:
			}
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
