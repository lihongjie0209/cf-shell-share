// Package crypto implements the Noise_NK_25519_ChaChaPoly_SHA256 handshake
// used to establish an end-to-end encrypted channel between host and viewer.
//
// Security model:
//   - The routing token (16 bytes) is visible to the relay but contains no key material.
//   - The host generates a Curve25519 static keypair each session.
//   - The invite = base64url(token || host_pubkey) is shared out-of-band.
//   - After the NK handshake the relay only forwards ChaCha20-Poly1305 ciphertext.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/flynn/noise"
)

const (
	TokenSize  = 32 // hex chars (16 random bytes → 32-char hex string)
	PubKeySize = 32 // Curve25519 public key bytes
	InviteSize = TokenSize + PubKeySize
)

// cipherSuite is Noise_NK_25519_ChaChaPoly_SHA256.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Handshake holds the two cipher states derived after the NK handshake.
// SendCS encrypts outbound messages; RecvCS decrypts inbound messages.
type Handshake struct {
	SendCS *noise.CipherState
	RecvCS *noise.CipherState
}

// GenerateKeypair creates a new Curve25519 static keypair for the host.
func GenerateKeypair() (noise.DHKey, error) {
	return cipherSuite.GenerateKeypair(rand.Reader)
}

// EncodeInvite encodes a routing token string and host public key into a
// base64url string embedded in the join URL path.
//
//	invite = base64url( token[32 bytes] || pubkey[32 bytes] )
func EncodeInvite(token string, pubKey []byte) string {
	buf := make([]byte, InviteSize)
	copy(buf[:TokenSize], token) // token is a 32-char hex string
	copy(buf[TokenSize:], pubKey)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// DecodeInvite reverses EncodeInvite.
// Returns the routing token string and host public key, or an error for
// malformed input.
func DecodeInvite(s string) (token string, pubKey []byte, err error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", nil, fmt.Errorf("invalid invite encoding: %w", err)
	}
	if len(b) != InviteSize {
		return "", nil, fmt.Errorf("invalid invite length %d (want %d)", len(b), InviteSize)
	}
	return string(b[:TokenSize]), b[TokenSize:], nil
}

// HostHandshake performs Noise_NK as the responder (host).
func HostHandshake(staticKey noise.DHKey, recv func() ([]byte, error), send func([]byte) error) (*Handshake, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: staticKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create handshake state: %w", err)
	}

	// Step 1: read viewer's first message (e, es)
	msg1, err := recv()
	if err != nil {
		return nil, fmt.Errorf("read handshake msg1: %w", err)
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("process handshake msg1: %w", err)
	}

	// Step 2: send host's reply (e, ee) — handshake complete after this
	out, c1, c2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write handshake msg2: %w", err)
	}
	if err := send(out); err != nil {
		return nil, fmt.Errorf("send handshake msg2: %w", err)
	}

	// c1 = initiator→responder channel (host receives on c1)
	// c2 = responder→initiator channel (host sends on c2)
	return &Handshake{SendCS: c2, RecvCS: c1}, nil
}

// ViewerHandshake performs Noise_NK as the initiator (viewer).
// hostPubKey must match the host's static public key embedded in the invite.
// If the relay tampers with the handshake, Decrypt will return an auth error.
func ViewerHandshake(hostPubKey []byte, recv func() ([]byte, error), send func([]byte) error) (*Handshake, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  hostPubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create handshake state: %w", err)
	}

	// Step 1: send viewer's first message (e, es)
	out, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write handshake msg1: %w", err)
	}
	if err := send(out); err != nil {
		return nil, fmt.Errorf("send handshake msg1: %w", err)
	}

	// Step 2: read host's reply (e, ee) — handshake complete
	msg2, err := recv()
	if err != nil {
		return nil, fmt.Errorf("read handshake msg2: %w", err)
	}
	_, c1, c2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("process handshake msg2 (possible relay tampering): %w", err)
	}

	// c1 = initiator→responder channel (viewer sends on c1)
	// c2 = responder→initiator channel (viewer receives on c2)
	return &Handshake{SendCS: c1, RecvCS: c2}, nil
}

// Encrypt encrypts plaintext with ChaCha20-Poly1305 using the send cipher state.
// Nonce is managed automatically by the cipher state (increments per message).
// Panics if the cipher state is exhausted (2^64 messages) — not reachable in practice.
func (h *Handshake) Encrypt(plaintext []byte) []byte {
	ct, err := h.SendCS.Encrypt(nil, nil, plaintext)
	if err != nil {
		panic("shellshare: cipher state encrypt: " + err.Error())
	}
	return ct
}

// Decrypt decrypts and authenticates ciphertext using the recv cipher state.
// Returns an error if authentication fails (tampered or out-of-order message).
func (h *Handshake) Decrypt(ciphertext []byte) ([]byte, error) {
	return h.RecvCS.Decrypt(nil, nil, ciphertext)
}
