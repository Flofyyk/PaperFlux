package transport

import (
	"encoding/binary"
	"fmt"
)

// UDP frames are deliberately separate from the existing raw-IP TCP path.
// This lets old peers continue to exchange TCP packets unchanged while new
// peers negotiate UDP/QUIC support explicitly.
const (
	udpFrameMagic   = "OUDP"
	udpFrameVersion = 1
	udpFrameHeader  = 20 // magic(4), version(1), flags(1), flow(4), len(4), reserved(6)
)

type UDPFrame struct {
	FlowID  uint32
	Flags   byte
	Payload []byte
}

func encodeUDPFrame(frame UDPFrame) ([]byte, error) {
	if len(frame.Payload) > 1<<16-1 {
		return nil, fmt.Errorf("udp frame payload too large: %d", len(frame.Payload))
	}
	out := make([]byte, udpFrameHeader+len(frame.Payload))
	copy(out[:4], udpFrameMagic)
	out[4] = udpFrameVersion
	out[5] = frame.Flags
	binary.BigEndian.PutUint32(out[6:10], frame.FlowID)
	binary.BigEndian.PutUint32(out[10:14], uint32(len(frame.Payload)))
	copy(out[udpFrameHeader:], frame.Payload)
	return out, nil
}

func decodeUDPFrame(data []byte) (UDPFrame, error) {
	if len(data) < udpFrameHeader || string(data[:4]) != udpFrameMagic || data[4] != udpFrameVersion {
		return UDPFrame{}, fmt.Errorf("invalid udp frame header")
	}
	n := int(binary.BigEndian.Uint32(data[10:14]))
	if n < 0 || n > 1<<16-1 || udpFrameHeader+n != len(data) {
		return UDPFrame{}, fmt.Errorf("invalid udp frame length: %d", n)
	}
	payload := make([]byte, n)
	copy(payload, data[udpFrameHeader:])
	return UDPFrame{FlowID: binary.BigEndian.Uint32(data[6:10]), Flags: data[5], Payload: payload}, nil
}
