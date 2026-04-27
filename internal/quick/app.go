package quick

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func Main(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "up":
		return up(args[1:])
	case "down":
		return down(args[1:])
	default:
		return usageError()
	}
}

func up(args []string) error {
	flags := flag.NewFlagSet("up", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	foreground := flags.Bool("f", false, "run in foreground")
	address := flags.String("address", "", "tun interface address")
	shortAddress := flags.String("a", "", "tun interface address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return usageError()
	}
	if *shortAddress != "" {
		*address = *shortAddress
	}
	if *address == "" {
		randomAddress, err := randomTunAddress()
		if err != nil {
			return err
		}
		*address = randomAddress
	}

	instance, err := NewInstance(flags.Arg(0))
	if err != nil {
		return err
	}

	if *foreground {
		return runForeground(instance, *address)
	}
	return startBackground(instance, *address)
}

func down(args []string) error {
	flags := flag.NewFlagSet("down", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return usageError()
	}

	instance, err := NewInstance(flags.Arg(0))
	if err != nil {
		return err
	}
	return deleteInterface(instance.InterfaceName)
}

func startBackground(instance Instance, address string) error {
	if interfaceExists(instance.InterfaceName) {
		return fmt.Errorf("interface %s already exists", instance.InterfaceName)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	commandArgs := []string{"up", "-f", "-a", address, instance.ConfigPath}
	printCommand(append([]string{filepath.Base(executable)}, commandArgs...)...)

	cmd := exec.Command(executable, commandArgs...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start background process: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if interfaceExists(instance.InterfaceName) {
			return nil
		}
		if !processAlive(cmd.Process.Pid) {
			return errors.New("background process exited before becoming ready; run with -f to see logs")
		}
		time.Sleep(100 * time.Millisecond)
	}

	_ = syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
	return errors.New("timed out waiting for background process; run with -f to see logs")
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func usageError() error {
	return errors.New("usage: v2ray-quick up [-f] [-a address|--address address] ./name.conf | v2ray-quick down ./name.conf")
}

func randomTunAddress() (string, error) {
	var bytes [2]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate random tun address: %w", err)
	}
	host := binary.BigEndian.Uint16(bytes[:])
	base := (host & 0x3fff) * 4
	address := base + 1
	return fmt.Sprintf("10.75.%d.%d/30", byte(address>>8), byte(address)), nil
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func deleteInterface(name string) error {
	cmd := exec.Command("ip", "link", "delete", "dev", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	printCommand(cmd.Args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("delete interface %s: %w", name, err)
	}
	return nil
}

func printCommand(args ...string) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	fmt.Printf("[#] %s\n", strings.Join(quoted, " "))
}

func shellQuote(arg string) string {
	if arg != "" && strings.IndexFunc(arg, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("_@%+=:,./-", r)
	}) == -1 {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
}
