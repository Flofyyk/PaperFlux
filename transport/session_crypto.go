package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Reuse only derivation within this Session, never between users. Each lane
// still receives separate AEAD objects and replay state. Wire keys, scrypt
// strength, domain separation and the Android handshake remain unchanged.
func (s *Session) wrapEncrypted(raw Transport, secret, context string) (*EncryptedTransport, error) {
	if raw == nil {
		return nil, errors.New("missing carrier")
	}
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(secret)))
	hash.Write(length[:])
	hash.Write([]byte(secret))
	hash.Write([]byte(context))
	var identity [32]byte
	copy(identity[:], hash.Sum(nil))
	s.encryptionMu.Lock()
	defer s.encryptionMu.Unlock()
	if s.encryptionCache == nil {
		s.encryptionCache = make(map[[32]byte]encryptionKeys)
	}
	keys, found := s.encryptionCache[identity]
	if !found {
		if len(s.encryptionCache) >= 8 {
			return nil, errors.New("session encryption context limit")
		}
		var err error
		keys, err = deriveEncryptionKeys(secret, context)
		if err != nil {
			return nil, err
		}
		s.encryptionCache[identity] = keys
	}
	return wrapEncryptionKeys(raw, keys, s.exit)
}
