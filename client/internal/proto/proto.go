// Package proto defines the binary framing protocol used inside the
// Noise-encrypted tunnel.
//
// Each plaintext message (before encryption) is:
//
//	[1 byte type] [payload bytes...]
//
// Message types:
//
//	0x00  MsgData   — raw terminal bytes (PTY output / user keystrokes)
//	0x01  MsgResize — terminal resize: 2 bytes cols (big-endian) + 2 bytes rows
//	0x02  MsgClose  — session teardown (no payload)
package proto

import (
	"encoding/binary"
	"fmt"
)

const (
	MsgData   byte = 0x00
	MsgResize byte = 0x01
	MsgClose  byte = 0x02
)

// Message is the decoded form of a single framed message.
type Message struct {
	Type byte
	Data []byte // MsgData: raw bytes
	Cols uint16 // MsgResize
	Rows uint16 // MsgResize
}

// EncodeData builds a MsgData frame.
func EncodeData(data []byte) []byte {
	frame := make([]byte, 1+len(data))
	frame[0] = MsgData
	copy(frame[1:], data)
	return frame
}

// EncodeResize builds a MsgResize frame.
func EncodeResize(cols, rows uint16) []byte {
	frame := make([]byte, 5)
	frame[0] = MsgResize
	binary.BigEndian.PutUint16(frame[1:3], cols)
	binary.BigEndian.PutUint16(frame[3:5], rows)
	return frame
}

// EncodeClose builds a MsgClose frame.
func EncodeClose() []byte {
	return []byte{MsgClose}
}

// Decode parses a raw plaintext frame into a Message.
func Decode(frame []byte) (*Message, error) {
	if len(frame) == 0 {
		return nil, fmt.Errorf("empty frame")
	}
	m := &Message{Type: frame[0]}
	switch frame[0] {
	case MsgData:
		m.Data = frame[1:]
	case MsgResize:
		if len(frame) < 5 {
			return nil, fmt.Errorf("resize frame too short (%d bytes)", len(frame))
		}
		m.Cols = binary.BigEndian.Uint16(frame[1:3])
		m.Rows = binary.BigEndian.Uint16(frame[3:5])
	case MsgClose:
		// no payload
	default:
		return nil, fmt.Errorf("unknown message type 0x%02x", frame[0])
	}
	return m, nil
}
