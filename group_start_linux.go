//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// Bound expensive derivations across all groups, without weakening the KDF.
// Busy profiles use the existing retry/backoff, so shutdown is not blocked.
func acquireGroupStartupSlot(directory string) (func(), error) {
	if directory == "" {
		return func() {}, nil
	}
	if !filepath.IsAbs(directory) || os.MkdirAll(directory, 0700) != nil {
		return nil, errors.New("private startup directory unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("startup directory must be private and owned")
	}
	for slot := 0; slot < 2; slot++ {
		fd, err := syscall.Open(filepath.Join(directory, "slot-"+strconv.Itoa(slot)), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return nil, errors.New("startup lock unavailable")
		}
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
			syscall.Close(fd)
			return nil, errors.New("startup lock must be a private regular file")
		}
		if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			var once sync.Once
			return func() { once.Do(func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd) }) }, nil
		}
		syscall.Close(fd)
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return nil, errors.New("startup lock failed")
		}
	}
	return nil, errors.New("group startup capacity busy")
}
