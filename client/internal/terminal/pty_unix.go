//go:build !windows

package terminal

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// StartPTY forks the given shell under a PTY with the given initial size.
// Returns the PTY master file, a channel that closes when the child exits,
// and any error.
func StartPTY(shell string, cols, rows uint16) (*os.File, <-chan struct{}, error) {
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, nil, err
	}

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	return ptmx, done, nil
}

// ResizePTY resizes the PTY to the given dimensions.
func ResizePTY(ptmx *os.File, cols, rows uint16) {
	_ = pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

// GetSize returns the current terminal dimensions.
func GetSize() (cols, rows uint16) {
	ws, err := pty.GetsizeFull(os.Stdin)
	if err != nil {
		return 80, 24
	}
	return ws.Cols, ws.Rows
}
