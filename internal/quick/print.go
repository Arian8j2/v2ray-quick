package quick

import (
	"flag"
	"io"
	"os"
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
	addressValue := *address
	if *shortAddress != "" {
		addressValue = *shortAddress
	}
	if addressValue != "" {
		if err := validateTunAddress(addressValue); err != nil {
			return err
		}
	}

	instance, err := NewInstance(flags.Arg(0))
	if err != nil {
		return err
	}
	return writeXrayConfigForInstance(os.Stdout, instance)
}

func writeXrayConfigForInstance(writer io.Writer, instance Instance) error {
	vless, err := LoadVLESS(instance.ConfigPath)
	if err != nil {
		return err
	}
	config, err := BuildConfig(vless, instance.InterfaceName)
	if err != nil {
		return err
	}
	return writeXrayConfig(writer, config)
}
