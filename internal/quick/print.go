package quick

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sagernet/sing/common/json"
)

func printConfig(args []string) error {
	flags := flag.NewFlagSet("print", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	address := flags.String("address", "", "tun interface address")
	shortAddress := flags.String("a", "", "tun interface address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return usageError()
	}
	addressValue, err := resolveTunAddress(*address, *shortAddress)
	if err != nil {
		return err
	}

	instance, err := NewInstance(flags.Arg(0))
	if err != nil {
		return err
	}
	return writeSingBoxConfig(os.Stdout, instance, addressValue)
}

func writeSingBoxConfig(writer io.Writer, instance Instance, address string) error {
	vless, err := LoadVLESS(instance.ConfigPath)
	if err != nil {
		return err
	}
	options, err := BuildOptions(vless, instance.InterfaceName, address)
	if err != nil {
		return err
	}

	encoder := json.NewEncoderContext(context.Background(), writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(options); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}
	return nil
}
