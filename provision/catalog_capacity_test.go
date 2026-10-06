package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLargePrivateCatalogKeepsIndividualResponseBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	rows := make([]Profile, MaxCatalogProfiles)
	for i := range rows {
		rows[i] = Profile{ID: fmt.Sprint(i + 1), Name: "Test", Token: fmt.Sprintf("%043d", i),
			ClientIP: fmt.Sprintf("10.10.%d.%d", 10+i/253, 2+i%253), Transport: "mailru",
			DocumentURL: "https://cloud.mail.ru/public/Test/" + strings.Repeat("a", 1500) + fmt.Sprint(i)}
	}
	body, err := json.Marshal(rows)
	if err != nil || len(body) <= 1<<20 || len(body) > MaxCatalogBytes {
		t.Fatal("invalid test catalog size", err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	// Match the executable: validate/cache before opening the TCP listener.
	source := FileSource(path)
	loaded, err := source()
	if err != nil || len(loaded) != MaxCatalogProfiles {
		t.Fatal("large catalog rejected", err)
	}
	if MaxPayload != 8192 {
		t.Fatal("individual encrypted response limit changed")
	}
	// A full catalog must admit its last identity and reject an unrelated key.
	service := &Service{Source: source}
	last := rows[len(rows)-1]
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, token := range []string{last.Token, strings.Repeat("z", 43)} {
		done := make(chan error, 1)
		go func() {
			server, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer server.Close()
			done <- service.Handle(server)
		}()
		response, err := Fetch(context.Background(), listener.Addr().String(), token)
		serverErr := <-done
		if token == last.Token {
			if err != nil || serverErr != nil || response.ID != last.ID || response.ClientIP != "10.10.89.14" || response.Token != "" {
				t.Fatal("last catalog profile not delivered securely", err, serverErr)
			}
		} else if err == nil || serverErr == nil {
			t.Fatal("unknown key admitted")
		}
	}
	rows = append(rows, rows[0])
	body, _ = json.Marshal(rows)
	os.WriteFile(path, body, 0600)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("over-capacity catalog accepted")
	}
}

func TestCachedCatalogInvalidatesOnAtomicRevocationAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	rows := []Profile{{ID: "1", Name: "Test", Token: strings.Repeat("x", 43), ClientIP: "10.10.11.2", Transport: "mailru", DocumentURL: "https://cloud.mail.ru/public/Test/Doc"}}
	body, _ := json.Marshal(rows)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	source := FileSource(path)
	first, err := source()
	if err != nil {
		t.Fatal(err)
	}
	again, err := source()
	if err != nil || &first[0] != &again[0] {
		t.Fatal("unchanged source was not cached", err)
	}
	temporary := path + ".next"
	os.WriteFile(temporary, []byte("[]"), 0600)
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
	if revoked, err := source(); err != nil || len(revoked) != 0 {
		t.Fatal("revoked credentials cached", err)
	}
	os.WriteFile(path, []byte("invalid"), 0600)
	if _, err := source(); err == nil {
		t.Fatal("malformed catalog accepted")
	}
	os.Remove(path)
	if _, err := source(); err == nil {
		t.Fatal("missing catalog accepted")
	}
}
