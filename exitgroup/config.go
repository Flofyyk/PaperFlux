// Package exitgroup implements bounded, independently authenticated profile
// groups. It never interprets Telegram/SSH credentials or public request paths.
package exitgroup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

const MaxProfiles = 64
const MaxManifestBytes = 256 << 10

type Profile struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	ClientIP  string   `json:"clientIp"`
	Transport string   `json:"transport"`
	Documents []string `json:"documents"`
	VolgaURL  string   `json:"volgaUrl,omitempty"`
	// Zero disables this optional process-epoch data limit. Fleet accounting
	// must reconcile final snapshots before deploying this mode for public use.
	MaxBytes uint64 `json:"maxBytes,omitempty"`
}
type Manifest struct {
	Version      int       `json:"version"`
	ValidUntil   int64     `json:"validUntil"`
	Profiles     []Profile `json:"profiles"`
	Acknowledged []string  `json:"acknowledged,omitempty"`
}

var yandex = regexp.MustCompile(`^https://disk\.yandex\.ru/i/[A-Za-z0-9_-]+$`)
var mailru = regexp.MustCompile(`^https://cloud\.mail\.ru/public/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$`)
var secret = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
var epochID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (m Manifest) Validate(now time.Time) error {
	if len(m.Acknowledged) > 2*MaxProfiles {
		return errors.New("too many accounting acknowledgements")
	}
	for _, epoch := range m.Acknowledged {
		if !epochID.MatchString(epoch) {
			return errors.New("invalid accounting acknowledgement")
		}
	}
	if m.Version != 1 || m.ValidUntil <= now.Unix() || m.ValidUntil > now.Add(5*time.Minute).Unix() || m.Profiles == nil || len(m.Profiles) > MaxProfiles {
		return errors.New("invalid manifest version, lease or capacity")
	}
	ids, keys, rooms := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range m.Profiles {
		id, err := strconv.Atoi(p.ID)
		if err != nil || id < 1 || id > 41535 || strconv.Itoa(id) != p.ID || ids[p.ID] || !secret.MatchString(p.Token) || keys[p.Token] {
			return errors.New("invalid or duplicate profile identity")
		}
		ip, err := netip.ParseAddr(p.ClientIP)
		if err != nil || !ip.Is4() || !validClientIP(ip) {
			return errors.New("invalid virtual address")
		}
		if len(p.Documents) == 0 || len(p.Documents) > 2 || (p.Transport != "yandex" && p.Transport != "mailru" && p.Transport != "vyandex") || (p.Transport != "yandex" && len(p.Documents) != 1) {
			return errors.New("invalid transport or document count")
		}
		for _, doc := range p.Documents {
			if len(doc) > 512 || (p.Transport != "mailru" && !yandex.MatchString(doc)) || (p.Transport == "mailru" && !mailru.MatchString(doc)) || rooms[doc] {
				return errors.New("invalid or duplicate document")
			}
			rooms[doc] = true
		}
		if p.VolgaURL != "" {
			if p.Transport != "yandex" || !yandex.MatchString(p.VolgaURL) || rooms[p.VolgaURL] {
				return errors.New("invalid or duplicate Volga document")
			}
			rooms[p.VolgaURL] = true
		}
		ids[p.ID] = true
		keys[p.Token] = true
	}
	return nil
}

// Match the controller's 20000-slot pool while retaining its original /24.
// A group still has its own small runtime limit; larger catalogs do not mean
// thousands of in-process transport stacks should be started together.
func validClientIP(ip netip.Addr) bool {
	parts := ip.As4()
	if parts[0] != 10 || parts[1] != 10 || parts[2] < 10 || parts[2] > 89 || parts[3] < 2 || parts[3] > 254 {
		return false
	}
	return int(parts[2]-10)*253+int(parts[3]-2) < 20000
}

func ReadManifest(path string, now time.Time) (Manifest, error) {
	var m Manifest
	f, err := os.Open(path)
	if err != nil {
		return m, errors.New("manifest unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxManifestBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return m, errors.New("manifest must be a private bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil || len(data) > MaxManifestBytes {
		return m, errors.New("manifest size invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil {
		return m, errors.New("invalid manifest JSON")
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return m, errors.New("trailing manifest content")
	}
	return m, m.Validate(now)
}
