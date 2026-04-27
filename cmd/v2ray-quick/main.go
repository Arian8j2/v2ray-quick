package main

import (
	"fmt"
	"os"

	"v2ray-quick/internal/quick"
)

func main() {
	if err := quick.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
