//go:build windows

package terminal

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/term"
)

// StartPTY on Windows runs the shell as a subprocess and pipes its I/O
// through a pair of in-process pipes. Full PTY (ConPTY) is not yet supported.
func StartPTY(shell string, cols, rows uint16) (*os.File, <-chan struct{}, error) {
	// Use a pipe pair to simulate PTY I/O
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create pipe: %w", err)
	}

	cmd := exec.Command(shell)
	cmd.Stdin = pr
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, nil, fmt.Errorf("start shell: %w", err)
	}

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	// Return pw as the "PTY master"; callers read/write through it
	return pw, done, nil
}

// ResizePTY is a no-op on Windows (ConPTY resize not implemented).
func ResizePTY(_ *os.File, _, _ uint16) {}

// GetSize returns the current console window dimensions.
func GetSize() (cols, rows uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 80, 24
	}
	return uint16(w), uint16(h)
}
