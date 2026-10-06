package provision

import (
	"errors"
	"os"
	"runtime"
	"sync"
)

// FileSource reuses an immutable validated catalog between atomic exporter
// updates. A larger catalog must not be decoded once per unauthenticated
// connection (up to 32 concurrent connections). Revocation or a permission
// failure invalidates the cache rather than serving the previous credentials.
func FileSource(path string) Source {
	var mu sync.Mutex
	var previous os.FileInfo
	var rows []Profile
	unchanged := func(a, b os.FileInfo) bool {
		return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime() && a.Mode() == b.Mode()
	}
	return func() ([]Profile, error) {
		mu.Lock()
		defer mu.Unlock()
		for attempt := 0; attempt < 2; attempt++ {
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() > MaxCatalogBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
				previous, rows = nil, nil
				return nil, errors.New("profile source unavailable or unsafe")
			}
			if unchanged(previous, info) {
				return rows, nil
			}
			previous, rows = nil, nil
			loaded, err := LoadFile(path)
			if err != nil {
				return nil, err
			}
			after, err := os.Stat(path)
			if err != nil {
				return nil, errors.New("profile source changed while reading")
			}
			if unchanged(info, after) {
				previous, rows = after, loaded
				return rows, nil
			}
		}
		return nil, errors.New("profile source changed while reading")
	}
}
