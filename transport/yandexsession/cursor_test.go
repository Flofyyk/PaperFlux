package yandex

import (
	"reflect"
	"testing"

	"universal-bypass-tool/transport"
)

func TestAllCursorRecordsAndKeepalive(t *testing.T) {
	tunnel := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	var got []string
	tunnel.Receive(func(packet []byte) { got = append(got, string(packet)) })
	tunnel.handleMessage(nil, []byte(`42["message",{"messages":[{"cursor":"18;---KA---"},{"cursor":"18;YQ=="},{"cursor":"18;!invalid!"},{"cursor":"18;Yg=="},{"type":"saveChanges","excelAdditionalInfo":"Yw=="}]}]`))
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("records lost or reordered: %v", got)
	}
	if tunnel.Stats().PacketsRecv != 3 {
		t.Fatal("incorrect receive count")
	}
}
