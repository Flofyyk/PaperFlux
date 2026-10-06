package provision

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// UnixActivator speaks only to a private local manager. No tokens are written
// to disk or logs; the manager rechecks a fingerprint against its current DB.
func UnixActivator(path string) func(Profile) (string, error) {
	return func(p Profile) (string, error) {
		c, err := net.DialTimeout("unix", path, 750*time.Millisecond)
		if err != nil {
			return "", errors.New("activation unavailable")
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		digest := sha256.Sum256([]byte(p.Token))
		request := struct {
			ID      string `json:"id"`
			KeyHash string `json:"keyHash"`
		}{p.ID, hex.EncodeToString(digest[:])}
		if err := json.NewEncoder(c).Encode(request); err != nil {
			return "", errors.New("activation unavailable")
		}
		body, err := bufio.NewReader(io.LimitReader(c, 129)).ReadBytes('\n')
		if err != nil || len(body) > 128 {
			return "", errors.New("invalid activation response")
		}
		var result struct {
			State string `json:"state"`
		}
		if json.Unmarshal(body, &result) != nil {
			return "", errors.New("invalid activation response")
		}
		return result.State, nil
	}
}
