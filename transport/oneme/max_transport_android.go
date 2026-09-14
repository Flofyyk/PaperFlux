//go:build android

package oneme

import (
	"fmt"

	"universal-bypass-tool/transport"
)

// The Android client currently ships the Yandex transport only. Keeping a
// small API-compatible placeholder prevents WebRTC's desktop-only dependency
// graph from being linked into the mobile binary.
type unavailableTransport struct{ *transport.BaseTransport }

func NewOneMeTransport(_ bool, _ string, _ int64, config transport.TransportConfig) *unavailableTransport {
	return &unavailableTransport{BaseTransport: transport.NewBaseTransport(config)}
}

func (t *unavailableTransport) Start() error {
	return fmt.Errorf("MAX transport is not included in this Android build")
}

func (t *unavailableTransport) Send([]byte) error {
	return fmt.Errorf("MAX transport is not included in this Android build")
}
