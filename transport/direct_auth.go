package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"
)

func directAdmission(c net.Conn, secret string, exit bool) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
	sign := func(role byte, p []byte) []byte {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte("paperflux-auth-service-v1"))
		m.Write([]byte{role})
		m.Write(p)
		return m.Sum(nil)
	}
	var server, client [32]byte
	var proof [32]byte
	if exit {
		if _, e := rand.Read(server[:]); e != nil {
			return e
		}
		if _, e := c.Write(server[:]); e != nil {
			return e
		}
		if _, e := io.ReadFull(c, client[:]); e != nil {
			return e
		}
		if _, e := io.ReadFull(c, proof[:]); e != nil {
			return e
		}
		pair := append(append([]byte(nil), server[:]...), client[:]...)
		if !hmac.Equal(proof[:], sign(1, pair)) {
			return fmt.Errorf("admission rejected")
		}
		_, e := c.Write(sign(2, pair))
		return e
	}
	if _, e := io.ReadFull(c, server[:]); e != nil {
		return e
	}
	if _, e := rand.Read(client[:]); e != nil {
		return e
	}
	pair := append(append([]byte(nil), server[:]...), client[:]...)
	if _, e := c.Write(append(client[:], sign(1, pair)...)); e != nil {
		return e
	}
	if _, e := io.ReadFull(c, proof[:]); e != nil {
		return e
	}
	if !hmac.Equal(proof[:], sign(2, pair)) {
		return fmt.Errorf("server admission rejected")
	}
	return nil
}
