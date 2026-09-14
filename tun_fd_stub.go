//go:build !android

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"universal-bypass-tool/transport"
)

func runTun2Socks(io.ReadWriteCloser, int, string, interface {
	DialUDP(string) (net.Conn, error)
}) error {
	return errors.New("tun2socks is only available on Android builds")
}

func configureAndroidResolver() {}

func recvTunFD(string) (*os.File, error) {
	return nil, fmt.Errorf("Android TUN mode is only available in Android builds")
}

func runTUNBridge(transport.Transport, *os.File) {}
