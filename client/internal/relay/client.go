// Package relay manages the WebSocket connection to the cf-shell-share relay
// Worker, performs the Noise_NK handshake over that connection, and provides
// Send/Recv primitives that transparently encrypt and decrypt every message.
package relay

import (
"encoding/json"
"fmt"
"io"
"net/http"
"net/url"
"strings"
"sync"

"github.com/flynn/noise"
"github.com/gorilla/websocket"
"github.com/lihongjie0209/shellshare/internal/crypto"
)

// Role identifies whether the client is the host or a viewer.
type Role string

const (
RoleHost   Role = "host"
RoleViewer Role = "viewer"
)

// Client wraps a WebSocket connection to the relay.
type Client struct {
conn *websocket.Conn
mu   sync.Mutex // serialises writes
}

// CreateSession calls POST /session on the relay server and returns the
// 32-char hex routing token and the DO location hint.
func CreateSession(serverURL string) (token, hint string, err error) {
resp, err := http.Post(serverURL+"/session", "application/json", nil)
if err != nil {
return "", "", fmt.Errorf("POST /session: %w", err)
}
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
if resp.StatusCode != http.StatusOK {
return "", "", fmt.Errorf("POST /session returned %d: %s", resp.StatusCode, body)
}
var result struct {
Token string `json:"token"`
Hint  string `json:"hint"`
}
if err := json.Unmarshal(body, &result); err != nil {
return "", "", fmt.Errorf("parse session response: %w", err)
}
if result.Token == "" {
return "", "", fmt.Errorf("empty token in session response")
}
return result.Token, result.Hint, nil
}

// Connect opens a WebSocket connection to the relay for the given session token.
// hint is the DO location hint returned by CreateSession (embedded in the invite).
func Connect(serverURL, token, hint string, role Role) (*Client, error) {
wsURL := strings.Replace(serverURL, "https://", "wss://", 1)
wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
u, err := url.Parse(wsURL + "/ws")
if err != nil {
return nil, err
}
q := u.Query()
q.Set("token", token)
q.Set("role", string(role))
if hint != "" {
	q.Set("hint", hint)
}
u.RawQuery = q.Encode()

conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
if err != nil {
return nil, fmt.Errorf("websocket dial %s: %w", u.String(), err)
}
return &Client{conn: conn}, nil
}

// Close closes the underlying WebSocket connection.
func (c *Client) Close() error {
return c.conn.Close()
}

func (c *Client) sendRaw(data []byte) error {
c.mu.Lock()
defer c.mu.Unlock()
return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *Client) recvRaw() ([]byte, error) {
_, data, err := c.conn.ReadMessage()
return data, err
}

// DoHostHandshake performs Noise_NK as the host (responder).
// Blocks until the viewer connects and the handshake completes.
func (c *Client) DoHostHandshake(staticKey noise.DHKey) (*crypto.Handshake, error) {
return crypto.HostHandshake(staticKey, c.recvRaw, c.sendRaw)
}

// DoViewerHandshake performs Noise_NK as the viewer (initiator).
func (c *Client) DoViewerHandshake(hostPubKey []byte) (*crypto.Handshake, error) {
return crypto.ViewerHandshake(hostPubKey, c.recvRaw, c.sendRaw)
}

// Send encrypts plaintext and sends it as one WebSocket binary frame.
func (c *Client) Send(hs *crypto.Handshake, plaintext []byte) error {
return c.sendRaw(hs.Encrypt(plaintext))
}

// Recv reads one WebSocket binary frame and decrypts it.
func (c *Client) Recv(hs *crypto.Handshake) ([]byte, error) {
ct, err := c.recvRaw()
if err != nil {
return nil, err
}
return hs.Decrypt(ct)
}
