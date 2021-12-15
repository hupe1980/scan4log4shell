package main

import "github.com/hupe1980/log4shellscan/cmd"

// nolint: gochecknoglobals
var version = "dev"

func main() {
	cmd.Execute(version)
}
