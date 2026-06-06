package cmd

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/lihongjie0209/shellshare/internal/crypto"
	"github.com/lihongjie0209/shellshare/internal/proto"
	"github.com/lihongjie0209/shellshare/internal/relay"
	"github.com/lihongjie0209/shellshare/internal/terminal"
	"github.com/spf13/cobra"
)

var (
	shareReadOnly bool
	shareShell    string
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Share your current shell session",
	RunE:  runShare,
}

func init() {
	shareCmd.Flags().BoolVar(&shareReadOnly, "ro", false, "Read-only: ignore viewer input")
	shareCmd.Flags().StringVar(&shareShell, "shell", "", "Shell to run (default: $SHELL or /bin/bash)")
}

func runShare(cmd *cobra.Command, args []string) error {
	// 1. Generate Noise static keypair for this session
	staticKey, err := crypto.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// 2. Create session on relay server → get routing token
	token, err := relay.CreateSession(serverURL)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	// 3. Build invite URL = <serverURL>/j/<base64url(token || host_pubkey)>
	//    The URL embeds both the relay server and all crypto material, so the
	//    viewer only needs to run: shellshare join <url>
	invite := crypto.EncodeInvite(token, staticKey.Public)
	joinURL := serverURL + "/j/" + invite

	// 4. Connect to relay as host
	wsClient, err := relay.Connect(serverURL, token, relay.RoleHost)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}
	defer wsClient.Close()

	// 5. Show join link AFTER connecting (so the relay session already exists)
	fmt.Fprintln(os.Stderr, "\r\n🔐 Shell Share — waiting for viewer...\r")
	fmt.Fprintf(os.Stderr, "\r\n  Share this link:\r\n\r\n  shellshare join %s\r\n\r\n", joinURL)
	fmt.Fprintln(os.Stderr, "  Press Ctrl+C to stop sharing.\r")

	// 6. Wait for viewer and perform Noise_NK handshake (host = responder)
	fmt.Fprintln(os.Stderr, "\r\n  ⏳ Waiting for viewer to connect...\r")
	hs, err := wsClient.DoHostHandshake(staticKey)
	if err != nil {
		return fmt.Errorf("noise handshake: %w", err)
	}
	fmt.Fprintln(os.Stderr, "  ✔ Viewer connected — session started\r")

	// 7. Start PTY
	shell := shareShell
	if shell == "" {
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
	}

	cols, rows := terminal.GetSize()
	ptmx, ptyClosed, err := terminal.StartPTY(shell, cols, rows)
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	defer ptmx.Close()

	// Send initial terminal size to viewer
	if err := wsClient.Send(hs, proto.EncodeResize(cols, rows)); err != nil {
		return fmt.Errorf("send initial size: %w", err)
	}

	// Handle terminal resize and forward to viewer (SIGWINCH on Unix, no-op on Windows)
	sigCh := make(chan os.Signal, 1)
	notifyResize(sigCh)
	go func() {
		for range sigCh {
			c, r := terminal.GetSize()
			terminal.ResizePTY(ptmx, c, r)
			_ = wsClient.Send(hs, proto.EncodeResize(c, r))
		}
	}()

	errCh := make(chan error, 2)

	// PTY output → encrypt → relay → viewer
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if err := wsClient.Send(hs, proto.EncodeData(buf[:n])); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Relay → decrypt → PTY input (viewer keystrokes)
	go func() {
		for {
			plaintext, err := wsClient.Recv(hs)
			if err != nil {
				errCh <- err
				return
			}
			msg, err := proto.Decode(plaintext)
			if err != nil {
				continue
			}
			switch msg.Type {
			case proto.MsgData:
				if !shareReadOnly {
					_, _ = ptmx.Write(msg.Data)
				}
			case proto.MsgResize:
				terminal.ResizePTY(ptmx, msg.Cols, msg.Rows)
			case proto.MsgClose:
				errCh <- nil
				return
			}
		}
	}()

	select {
	case <-ptyClosed:
		fmt.Fprintln(os.Stderr, "\r\n  Shell exited.\r")
		_ = wsClient.Send(hs, proto.EncodeClose())
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "\r\n  Session error: %v\r\n", err)
		}
	}

	signal.Stop(sigCh)
	return nil
}
