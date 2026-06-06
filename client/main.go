package main

import (
	"fmt"
	"os"

	"github.com/lihongjie0209/shellshare/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
