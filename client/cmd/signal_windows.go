//go:build windows

package cmd

import "os"

// notifyResize is a no-op on Windows — terminal resize events are not
// delivered as OS signals; the viewer polls size on each read instead.
func notifyResize(_ chan<- os.Signal) {}
