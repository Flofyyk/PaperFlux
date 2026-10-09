package mailru

import (
	"os"
	"path/filepath"
	"testing"
	"universal-bypass-tool/transport"
)

// Opt-in: the runner supplies only an owned test document, through the process
// environment. No links, cookie values or editor metadata are logged.
func TestLiveMailru429MetadataRecoveryAndRestart(t *testing.T) {
	privateURL := os.Getenv("PAPERFLUX_MAILRU_LIVE_TEST_URL")
	if privateURL == "" {
		t.Skip("owned document not configured")
	}
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "verification.json"))
	if err != nil {
		t.Fatal("cannot create test cookie store")
	}
	tr := NewMailruDocsTransport(privateURL, transport.DefaultConfig())
	saved := 0
	tr.SetCookieSaver(func(service map[string]string) error { saved++; return store.Save("owned-test", service) })
	if _, err := tr.fetchDocInfo(tr.weblink); err != nil {
		t.Fatalf("initial metadata recovery: %v", err)
	}
	reopened, err := transport.NewCookieStore(store.Path())
	if err != nil {
		t.Fatal("cannot reopen test cookie store")
	}
	next := NewMailruDocsTransport(privateURL, transport.DefaultConfig())
	next.RestoreVerificationCookies(reopened.Load("owned-test"))
	secondConfirmation := 0
	next.SetCookieSaver(func(service map[string]string) error { secondConfirmation++; return nil })
	if _, err := next.fetchDocInfo(next.weblink); err != nil {
		t.Fatalf("metadata after cookie restore: %v", err)
	}
	t.Logf("metadata_ok=true first_confirmations=%d restored_service_cookies=%d second_confirmations=%d", saved, len(reopened.Load("owned-test")), secondConfirmation)
}
