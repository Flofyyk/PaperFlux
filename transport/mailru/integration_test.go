package mailru

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

func TestLargeCursorBatchIsDeliveredInOrder(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	var got [][]byte
	tr.Receive(func(p []byte) { got = append(got, p) })
	payload := base64.StdEncoding.EncodeToString([]byte("first"))
	frame := `42["message",{"padding":"` + strings.Repeat("x", 300<<10) + `","type":"cursor","cursors":[{"cursor":"18;` + payload + `"},{"cursor":"18;c2Vjb25k"}]}]`
	tr.handleMessage(&DocSession{}, []byte(frame))
	if len(got) != 2 || string(got[0]) != "first" || string(got[1]) != "second" {
		t.Fatal("large batch lost or reordered packets")
	}
}

func TestReadOnlyMetadataRemainsUsable(t *testing.T) {
	info, err := parseMailruDocInfo([]byte(strings.Replace(testMetadata, `"edit":true`, `"edit":false`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if canEdit(info.Permissions) {
		t.Fatal("read-only document must not receive saveChanges")
	}
}

func TestAccountCookiesNeverLeaveTransport(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	if err := tr.ApplyCookies(map[string]string{"Mpop": "private-account", "m_auth2": "private-account", "anonymous-captcha": "public-challenge"}); err != nil {
		t.Fatal(err)
	}
	cookies, err := tr.FetchCookies()
	if err != nil || cookies["anonymous-captcha"] != "public-challenge" {
		t.Fatal("anonymous challenge cookie lost")
	}
	if len(cookies) != 1 {
		t.Fatal("account credentials shared")
	}
}

func TestReconnectWaitCancelledByStop(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	_ = tr.BaseTransport.Start()
	exited := make(chan struct{})
	go func() { tr.scheduleReconnect(10); close(exited) }()
	time.Sleep(20 * time.Millisecond)
	_ = tr.Stop()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("reconnect remained blocked")
	}
}

func TestSaveChangesStillMatchesOriginalTemplate(t *testing.T) {
	want := []byte(strings.ReplaceAll(strings.Replace(saveChangesMessageTemplate, "%s", "user12", 1), "%s", "user1"))
	if !bytes.Equal(BuildSaveChanges("user12"), want) {
		t.Fatal("editor activity differs from original")
	}
}
