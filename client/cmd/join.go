package cmd

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/lihongjie0209/shellshare/internal/crypto"
	"github.com/lihongjie0209/shellshare/internal/proto"
	"github.com/lihongjie0209/shellshare/internal/relay"
	"github.com/lihongjie0209/shellshare/internal/terminal"
	"github.com/spf13/cobra"
	gterm "golang.org/x/term"
)

var joinCmd = &cobra.Command{
	Use:   "join <link>",
	Short: "Join a shared shell session",
	Long: `Join a shared shell session using the link produced by 'shellshare share'.

  shellshare join https://sh.lihongjie.cn/j/a3f8...

The link contains the relay server address and all crypto material needed to
establish an end-to-end encrypted connection. The relay server never sees the
decrypted content.`,
	Args: cobra.ExactArgs(1),
	RunE: runJoin,
}

// parseJoinURL accepts either a full join URL or a bare invite token.
//
//   https://sh.lihongjie.cn/j/<invite>?h=apac  →  server, invite, hint
//   <bare-invite>                               →  server from --server flag, no hint
func parseJoinURL(arg, flagServer string) (serverURL, invite, hint string, err error) {
	if !strings.HasPrefix(arg, "http://") && !strings.HasPrefix(arg, "https://") {
		return flagServer, arg, "", nil
	}
	u, err := url.Parse(arg)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid link: %w", err)
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if len(parts) != 2 || parts[0] != "j" || parts[1] == "" {
		return "", "", "", fmt.Errorf("link must be in the form <server>/j/<invite>, got path %q", u.Path)
	}
	server := u.Scheme + "://" + u.Host
	return server, parts[1], u.Query().Get("h"), nil
}

func runJoin(cmd *cobra.Command, args []string) error {
	joinServer, invite, hint, err := parseJoinURL(args[0], serverURL)
	if err != nil {
		return err
	}

	// 1. Decode invite → routing token + host public key
	token, hostPubKey, err := crypto.DecodeInvite(invite)
	if err != nil {
		return fmt.Errorf("invalid invite in link: %w", err)
	}

	// 2. Connect to relay as viewer, passing hint so the WS routes to the same DO
	client, err := relay.Connect(joinServer, token, hint, relay.RoleViewer)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}
	defer client.Close()

	fmt.Fprintln(os.Stderr, "\r\n🔐 Shell Share — connecting...\r")

	// 3. Noise_NK handshake (viewer = initiator, knows host pubkey).
	//    If the relay tampers with the handshake the AEAD auth will fail.
	hs, err := client.DoViewerHandshake(hostPubKey)
	if err != nil {
		return fmt.Errorf("noise handshake failed (wrong host or tampered relay): %w", err)
	}
	fmt.Fprintln(os.Stderr, "  ✔ Connected and authenticated\r\n  Press Ctrl+C to disconnect.\r\n")

	// 4. Switch terminal to raw mode
	oldState, err := gterm.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("set raw mode: %w", err)
	}
	defer gterm.Restore(int(os.Stdin.Fd()), oldState)

	// Send our terminal size to the host so its PTY can match
	cols, rows := terminal.GetSize()
	if err := client.Send(hs, proto.EncodeResize(cols, rows)); err != nil {
		return err
	}

	// Forward local resize events to host (SIGWINCH on Unix, no-op on Windows)
	sigCh := make(chan os.Signal, 1)
	notifyResize(sigCh)
	go func() {
		for range sigCh {
			c, r := terminal.GetSize()
			_ = client.Send(hs, proto.EncodeResize(c, r))
		}
	}()

	errCh := make(chan error, 2)

	// Relay → decrypt → stdout (host PTY output)
	go func() {
		for {
			plaintext, err := client.Recv(hs)
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
				_, _ = os.Stdout.Write(msg.Data)
			case proto.MsgResize:
				// host telling us its PTY size — nothing to do on viewer side
			case proto.MsgClose:
				errCh <- nil
				return
			}
		}
	}()

	// stdin → encrypt → relay → host PTY input
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if err == io.EOF {
					_ = client.Send(hs, proto.EncodeClose())
					errCh <- nil
				} else {
					errCh <- err
				}
				return
			}
			if err := client.Send(hs, proto.EncodeData(buf[:n])); err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	signal.Stop(sigCh)
	if err != nil && err.Error() != "" {
		fmt.Fprintf(os.Stderr, "\r\n  Session ended: %v\r\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "\r\n  Session ended.\r")
	}
	return nil
}
