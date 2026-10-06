//go:build !linux

package main

import "errors"

func acquireGroupStartupSlot(directory string) (func(), error) {
	if directory == "" {
		return func() {}, nil
	}
	return nil, errors.New("group startup locking requires Linux")
}
