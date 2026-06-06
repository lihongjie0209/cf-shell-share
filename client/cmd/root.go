package cmd

import (
	"github.com/spf13/cobra"
)

var serverURL string

var rootCmd = &cobra.Command{
	Use:   "shellshare",
	Short: "End-to-end encrypted shell sharing via Cloudflare Workers (Noise_NK)",
	Long: `shellshare — share your terminal session with end-to-end encryption.

The Cloudflare Worker relay only forwards opaque ciphertext (Noise_NK /
ChaCha20-Poly1305). Even the relay server cannot decrypt the session content.

Usage:
  shellshare share              # start sharing, outputs an invite token
  shellshare join <invite>      # join a shared session`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "https://sh.lihongjie.cn",
		"Relay server URL")
	rootCmd.AddCommand(shareCmd)
	rootCmd.AddCommand(joinCmd)
}
