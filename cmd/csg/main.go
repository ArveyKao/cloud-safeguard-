// Command csg is the Cloud Safeguard control plane and client CLI.
package main

import (
	"os"

	"github.com/arveykao/cloud-safeguard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
