package internal

import (
	"fmt"
	"os"
)

var (
	logFile = os.Stdout
	errFile = os.Stderr
)

func PrintError(format string, a ...interface{}) {
	fmt.Fprintf(errFile, format, a...)
}

func PrintInfo(format string, a ...interface{}) {
	fmt.Fprintf(logFile, format, a...)
}
