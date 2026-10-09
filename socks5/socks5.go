package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"universal-bypass-tool/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer
	ready      chan struct{}
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer, ready: make(chan struct{})}
}

func (s *SOCKS5Server) Ready() <-chan struct{} { return s.ready }

func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return s.Serve(listener)
}

// Serve also permits isolated integration tests with an ephemeral loopback port.
func (s *SOCKS5Server) Serve(listener net.Listener) error {
	close(s.ready)

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	targetAddr, err := readConnectRequest(clientConn)
	if err != nil {
		return
	}

	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)

	targetConn, err := s.dialer.DialTCP(targetAddr)
	if err != nil {
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()
	_ = clientConn.SetDeadline(time.Time{})

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer targetConn.Close()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// SOCKS handshakes may be fragmented or coalesced arbitrarily by TCP. Never
// assume a Read contains a whole message or slice with unchecked domain lengths.
func readConnectRequest(conn net.Conn) (string, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return "", fmt.Errorf("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 255})
		return "", fmt.Errorf("no supported auth method")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	reject := func(code byte) (string, error) {
		_, _ = conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported SOCKS request")
	}
	if header[0] != 5 || header[2] != 0 {
		return reject(1)
	}
	if header[1] != 1 {
		return reject(7)
	} // TCP CONNECT only; never bypass UDP.
	var host string
	switch header[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return reject(8)
		}
		domain := make([]byte, int(size[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	default:
		return reject(8) // native data path currently supports IPv4 only.
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	if binary.BigEndian.Uint16(port[:]) == 0 {
		return reject(1)
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}
