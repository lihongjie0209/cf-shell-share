//go:build windows

package terminal

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"golang.org/x/term"
)

// winPTY wraps a pair of OS pipes to simulate a PTY on Windows.
// stdinW  → shell reads from stdinR  (we write input here)
// stdoutW ← shell writes to stdoutW (we read output here)
type winPTY struct {
	stdinW  *os.File // write shell input here
	stdoutR *os.File // read shell output from here
	// keep write-end of stdout open so shell doesn't see EOF
	stdoutW *os.File
}

func (p *winPTY) Read(b []byte) (int, error)  { return p.stdoutR.Read(b) }
func (p *winPTY) Write(b []byte) (int, error) { return p.stdinW.Write(b) }
func (p *winPTY) Close() error {
	p.stdinW.Close()
	p.stdoutW.Close()
	return p.stdoutR.Close()
}

// StartPTY on Windows runs the shell with stdin/stdout connected via OS pipes.
func StartPTY(shell string, cols, rows uint16) (io.ReadWriteCloser, <-chan struct{}, error) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create stdin pipe: %w", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		return nil, nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	cmd := exec.Command(shell)
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stdoutW
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	if err := cmd.Start(); err != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return nil, nil, fmt.Errorf("start shell: %w", err)
	}
	// Shell now has its own copies of stdinR and stdoutW; close our copies.
	stdinR.Close()

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		stdoutW.Close() // signal EOF to our reader
		close(done)
	}()

	return &winPTY{stdinW: stdinW, stdoutR: stdoutR, stdoutW: stdoutW}, done, nil
}

// ResizePTY is a no-op on Windows.
func ResizePTY(_ io.ReadWriteCloser, _, _ uint16) {}

// GetSize returns the current console window dimensions.
func GetSize() (cols, rows uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 80, 24
	}
	return uint16(w), uint16(h)
}
