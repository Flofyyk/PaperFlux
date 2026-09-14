package relayv2

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

const (
	maxFrame = 1 << 20
	header   = 24
	frameTCP = 1
	frameUDP = 3
)

type Config struct {
	URL, Token, Session, Role string
	UserID                    uint64
}

type Transport struct {
	*transport.BaseTransport
	config Config
	mu     sync.RWMutex
	write  sync.Mutex
	conn   *websocket.Conn
}

func New(config Config, base transport.TransportConfig) (*Transport, error) {
	if config.URL == "" || config.UserID == 0 || config.Session == "" || (config.Role != "client" && config.Role != "exit") {
		return nil, fmt.Errorf("relay v2: URL, user, session and role are required")
	}
	return &Transport{BaseTransport: transport.NewBaseTransport(base), config: config}, nil
}
func (t *Transport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}
	go t.loop()
	return nil
}
func (t *Transport) Stop() error {
	_ = t.BaseTransport.Stop()
	t.mu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()
	return nil
}
func (t *Transport) Send(data []byte) error {
	if len(data) > maxFrame {
		return fmt.Errorf("relay v2: packet too large")
	}
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()
	if conn == nil || !t.IsConnected() {
		return fmt.Errorf("relay v2: not connected")
	}
	stream, kind := streamForPacket(data)
	wire := encode(kind, t.config.UserID, stream, data)
	t.write.Lock()
	err := conn.WriteMessage(websocket.BinaryMessage, wire)
	t.write.Unlock()
	if err != nil {
		t.SetConnected(false)
		return err
	}
	t.RecordSend(len(data))
	return nil
}
func (t *Transport) loop() {
	for t.IsRunning() {
		if err := t.connectAndRead(); err != nil {
			t.SetConnected(false)
			t.RecordReconnect()
			time.Sleep(t.GetConfig().ReconnectDelay)
		}
	}
}
func (t *Transport) connectAndRead() error {
	u, err := url.Parse(t.config.URL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("user", strconv.FormatUint(t.config.UserID, 10))
	q.Set("session", t.config.Session)
	q.Set("role", t.config.Role)
	u.RawQuery = q.Encode()
	h := http.Header{}
	if t.config.Token != "" {
		h.Set("Authorization", "Bearer "+t.config.Token)
	}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), h)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	t.SetConnected(true)
	defer func() {
		t.mu.Lock()
		if t.conn == conn {
			t.conn = nil
		}
		t.mu.Unlock()
		_ = conn.Close()
	}()
	for t.IsRunning() {
		typ, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		if typ != websocket.BinaryMessage {
			return fmt.Errorf("relay v2: expected binary frame")
		}
		kind, user, _, payload, err := decode(data)
		if err != nil || user != t.config.UserID {
			return fmt.Errorf("relay v2: invalid inbound frame")
		}
		if kind == frameTCP || kind == frameUDP {
			t.RecordReceive(len(payload))
			t.CallReceive(payload)
		}
	}
	return nil
}
func encode(kind byte, user uint64, stream uint32, payload []byte) []byte {
	out := make([]byte, header+len(payload))
	copy(out[:4], "OFLX")
	out[4] = 2
	out[5] = kind
	binary.BigEndian.PutUint64(out[8:16], user)
	binary.BigEndian.PutUint32(out[16:20], stream)
	binary.BigEndian.PutUint32(out[20:24], uint32(len(payload)))
	copy(out[header:], payload)
	return out
}
func decode(data []byte) (byte, uint64, uint32, []byte, error) {
	if len(data) < header || string(data[:4]) != "OFLX" || data[4] != 2 {
		return 0, 0, 0, nil, fmt.Errorf("relay v2: bad frame")
	}
	n := int(binary.BigEndian.Uint32(data[20:24]))
	if n > maxFrame || len(data) != header+n {
		return 0, 0, 0, nil, fmt.Errorf("relay v2: bad length")
	}
	return data[5], binary.BigEndian.Uint64(data[8:16]), binary.BigEndian.Uint32(data[16:20]), data[header:], nil
}
func streamForPacket(p []byte) (uint32, byte) {
	if len(p) < 24 || p[0]>>4 != 4 {
		return 1, frameTCP
	}
	h := int(p[0]&15) * 4
	if h < 20 || len(p) < h+4 {
		return 1, frameTCP
	}
	proto := p[9]
	kind := byte(frameTCP)
	if proto == 17 {
		kind = frameUDP
	}
	var v uint32 = 2166136261
	for _, b := range append(append([]byte{proto}, p[12:16]...), append(p[16:20], p[h:h+4]...)...) {
		v ^= uint32(b)
		v *= 16777619
	}
	if v == 0 {
		v = 1
	}
	return v, kind
}
