package mailru

import (
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

func TestStaleReaderCannotDisconnectReplacement(t *testing.T) {
	tr := NewMailruDocsTransport("Ab/Cd", transport.DefaultConfig())
	oldSession := &DocSession{}
	newSession := &DocSession{}
	tr.session = newSession
	tr.SetConnected(true)
	if tr.dropSession(oldSession) {
		t.Fatal("stale reader claimed the current session")
	}
	if !tr.IsConnected() || tr.session != newSession {
		t.Fatal("stale reader disconnected the replacement")
	}
	if !tr.dropSession(newSession) || tr.IsConnected() || tr.session != nil {
		t.Fatal("current reader did not release its session")
	}
}

func TestWriteQueueSurvivesSessionRotation(t *testing.T) {
	tr := NewMailruDocsTransport("Ab/Cd", transport.DefaultConfig())
	tr.writeQueue = make(chan []byte, 2)
	first := &DocSession{}
	tr.session = first
	tr.SetConnected(true)
	data := []byte("one")
	if err := tr.Send(data); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	tr.dropSession(first)
	tr.session = &DocSession{}
	tr.SetConnected(true)
	if err := tr.Send([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if got := string(<-tr.writeQueue); got != "one" {
		t.Fatalf("queued packet was mutated: %q", got)
	}
	if got := string(<-tr.writeQueue); got != "two" {
		t.Fatalf("queue was replaced on reconnect: %q", got)
	}
}

func TestIdleWriterStopsWithoutPacket(t *testing.T) {
	tr := NewMailruDocsTransport("Ab/Cd", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatal(err)
	}
	tr.writeQueue = make(chan []byte, 1)
	exited := make(chan struct{})
	go func() { tr.writerLoop(); close(exited) }()
	tr.Stop()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("writer remained blocked after Stop")
	}
}
