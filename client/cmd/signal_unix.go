//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyResize subscribes sigCh to SIGWINCH (terminal resize) signals.
func notifyResize(sigCh chan<- os.Signal) {
	signal.Notify(sigCh, syscall.SIGWINCH)
}
