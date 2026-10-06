package provision

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Fetch is a bounded authenticated client useful for deployment health checks.
// Possession of the profile token is required; responses never contain it.
func Fetch(ctx context.Context, address, token string) (Profile, error) {
	var p Profile
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return p, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	hello := make([]byte, 37)
	if _, err = io.ReadFull(c, hello); err != nil {
		return p, err
	}
	if string(hello[:5]) != Magic {
		return p, errors.New("invalid discovery hello")
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return p, err
	}
	pair := append(append([]byte{}, hello[5:]...), nonce...)
	lookup := Sign(token, "paperflux-profile-lookup-v1", nil)
	proof := Sign(token, "paperflux-profile-client-v1", append(append([]byte{}, pair...), lookup...))
	if _, err = c.Write(append(append(nonce, lookup...), proof...)); err != nil {
		return p, err
	}
	status := make([]byte, 1)
	if _, err = io.ReadFull(c, status); err != nil {
		return p, err
	}
	if status[0] != 1 {
		return p, errors.New("profile admission rejected")
	}
	header := make([]byte, 16)
	if _, err = io.ReadFull(c, header); err != nil {
		return p, err
	}
	length := binary.BigEndian.Uint32(header[12:])
	if length < 16 || length > MaxPayload+16 {
		return p, errors.New("invalid discovery length")
	}
	sealed := make([]byte, length)
	if _, err = io.ReadFull(c, sealed); err != nil {
		return p, err
	}
	block, _ := aes.NewCipher(Sign(token, "paperflux-profile-response-v1", pair))
	aead, _ := cipher.NewGCM(block)
	body, err := aead.Open(nil, header[:12], sealed, append([]byte(Magic), pair...))
	if err != nil {
		return p, errors.New("invalid discovery authentication")
	}
	if json.Unmarshal(body, &p) != nil || p.Token != "" {
		return Profile{}, errors.New("invalid discovery profile")
	}
	return p, nil
}
