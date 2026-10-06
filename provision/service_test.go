package provision

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedProfileAndWrongPassword(t *testing.T) {
	secret := strings.Repeat("x", 43)
	s := &Service{Source: func() ([]Profile, error) {
		return []Profile{{ID: "7", Name: "Example", Token: secret, ClientIP: "10.10.10.2", Transport: "yandex", DocumentURL: "https://disk.yandex.ru/i/example", VolgaURL: "https://disk.yandex.ru/i/empty_volga"}}, nil
	}}
	for _, password := range []string{secret, strings.Repeat("y", 43)} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { defer server.Close(); done <- s.Handle(server) }()
		hello := make([]byte, 37)
		if _, err := io.ReadFull(client, hello); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 32)
		rand.Read(nonce)
		pair := append(append([]byte{}, hello[5:]...), nonce...)
		lookup := Sign(password, "paperflux-profile-lookup-v1", nil)
		proof := Sign(password, "paperflux-profile-client-v1", append(append([]byte{}, pair...), lookup...))
		client.Write(append(append(nonce, lookup...), proof...))
		status := make([]byte, 1)
		io.ReadFull(client, status)
		if password != secret {
			if status[0] != 0 {
				t.Fatal("wrong key accepted")
			}
			client.Close()
			<-done
			continue
		}
		if status[0] != 1 {
			t.Fatal("valid key rejected")
		}
		header := make([]byte, 16)
		io.ReadFull(client, header)
		sealed := make([]byte, binary.BigEndian.Uint32(header[12:]))
		io.ReadFull(client, sealed)
		block, _ := aes.NewCipher(Sign(password, "paperflux-profile-response-v1", pair))
		aead, _ := cipher.NewGCM(block)
		body, err := aead.Open(nil, header[:12], sealed, append([]byte(Magic), pair...))
		if err != nil {
			t.Fatal(err)
		}
		var p Profile
		json.Unmarshal(body, &p)
		if p.ID != "7" || p.Token != "" || p.VolgaURL != "https://disk.yandex.ru/i/empty_volga" || strings.Contains(string(body), secret) {
			t.Fatal("invalid or leaking response")
		}
		sealed[0] ^= 1
		if _, err = aead.Open(nil, header[:12], sealed, append([]byte(Magic), pair...)); err == nil {
			t.Fatal("tampered response accepted")
		}
		client.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrivateFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	body := `[{"id":"1","name":"Test","token":"` + strings.Repeat("x", 43) + `","clientIp":"10.10.10.2","transport":"yandex","documentUrl":"https://disk.yandex.ru/i/example"}]`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatal(err)
	}
	volga := strings.Replace(body, `"documentUrl":"https://disk.yandex.ru/i/example"`,
		`"documentUrl":"https://disk.yandex.ru/i/example","volgaUrl":"https://disk.yandex.ru/i/empty_volga"`, 1)
	os.WriteFile(path, []byte(volga), 0600)
	if rows, err := LoadFile(path); err != nil || rows[0].VolgaURL != "https://disk.yandex.ru/i/empty_volga" {
		t.Fatal("Volga field was not preserved", err)
	}
	os.WriteFile(path, []byte(strings.Replace(volga, "empty_volga", "example", 1)), 0600)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("reused Volga document accepted")
	}
	os.WriteFile(path, []byte(body+` {}`), 0600)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	os.WriteFile(path, []byte(`[{"id":"1","token":"short"}]`), 0600)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("invalid profile accepted")
	}
}
