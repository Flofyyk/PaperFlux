//go:build !android

package main

import (
    "fmt"
    "io"
)

func connectPacketBridge(string) (io.ReadWriteCloser, error) {
    return nil, fmt.Errorf("packet bridge is supported only on Android")
}
