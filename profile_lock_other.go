//go:build !linux

package main

import "errors"

func acquireProfileLock(path string) (func(), error) {
	return nil, errors.New("exit profile groups require Linux locking")
}
