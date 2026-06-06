//go:build !windows

package terminal

import (
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type unixPTY struct{ f *os.File }

func (p *unixPTY) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *unixPTY) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p *unixPTY) Close() error                { return p.f.Close() }

// StartPTY forks the given shell under a PTY with the given initial size.
func StartPTY(shell string, cols, rows uint16) (io.ReadWriteCloser, <-chan struct{}, error) {
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

	return &unixPTY{ptmx}, done, nil
}

// ResizePTY resizes the PTY to the given dimensions.
func ResizePTY(p io.ReadWriteCloser, cols, rows uint16) {
	if u, ok := p.(*unixPTY); ok {
		_ = pty.Setsize(u.f, &pty.Winsize{Cols: cols, Rows: rows})
	}
}

// GetSize returns the current terminal dimensions.
func GetSize() (cols, rows uint16) {
	ws, err := pty.GetsizeFull(os.Stdin)
	if err != nil {
		return 80, 24
	}
	return ws.Cols, ws.Rows
}
