package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
	"universal-bypass-tool/socks5"
)

// Real SOCKS negotiation -> real gVisor TCP -> packet transport -> proxy exit
// -> real echo server. No OS TUN or direct target dial exists on the client.
func TestProxyTCPUsesExitWithoutTun(t *testing.T) {
	ip := testLANIPv4(t)
	echo, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	a, b := newTransportPair()
	clientStack := NewTCPTunnel(a, false)
	defer clientStack.Close()
	exit := NewTCPTunnelWithClientIPMode(b, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
	defer exit.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := socks5.NewSOCKS5Server(listener.Addr().String(), NewProxyDialer(clientStack))
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(listener) }()
	defer func() { listener.Close(); <-done }()
	<-proxy.Ready()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	ack := make([]byte, 2)
	if _, err := io.ReadFull(conn, ack); err != nil {
		t.Fatal(err)
	}
	port := echo.Addr().(*net.TCPAddr).Port
	request := append([]byte{5, 1, 0, 1}, ip.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	for _, value := range request {
		if _, err := conn.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("proxy refused target: %x", reply)
	}
	payload := bytes.Repeat([]byte("paperflux-proxy-integrity"), 1400)
	writeDone := make(chan error, 1)
	go func() { _, err := conn.Write(payload); writeDone <- err }()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, response) {
		t.Fatal("proxy data corruption")
	}
}
