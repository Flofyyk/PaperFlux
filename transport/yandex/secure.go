package yandex

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// PFS2 uses fresh random endpoint epochs and a PSK-authenticated challenge
// exchange. No cleartext identity/token is sent to the document provider.
// Every data key binds both epochs and direction. Restarting either endpoint
// therefore invalidates captured packets. Epochs are ephemeral X25519 public
// keys; traffic keys also require their DH secret (forward secrecy after the
// ephemeral private keys are discarded).
var secureMagic = []byte("PFS2")
var errSecure = errors.New("secure channel: rejected frame")

const secureHeader = 4 + 1 + 1 + 32 + 32 + 8
const maxSecureFrame = 128 << 10

type secureChannel struct {
	mu                  sync.Mutex
	master              []byte
	private             *ecdh.PrivateKey
	role                byte
	local, peer         [32]byte
	havePeer, confirmed bool
	send                cipher.AEAD
	recv                cipher.AEAD
	seq, high, bitmap   uint64
	seen                bool
	retired             map[[32]byte]bool
}

func newSecureChannel(profile, token, document string, exit bool) (*secureChannel, error) {
	if profile == "" || len(token) < 32 {
		return nil, fmt.Errorf("secure profile requires ID and a random token of at least 32 characters")
	}
	salt := sha256.Sum256([]byte("PaperFlux/PFS2/" + profile + "\x00" + document))
	master, err := scrypt.Key([]byte(token), salt[:], 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	c := &secureChannel{master: master, retired: make(map[[32]byte]bool)}
	if exit {
		c.role = 1
	}
	c.private, err = ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}
	copy(c.local[:], c.private.PublicKey().Bytes())
	return c, nil
}

func (c *secureChannel) mac(data []byte) []byte {
	h := hmac.New(sha256.New, c.master)
	h.Write(data)
	return h.Sum(nil)
}
func (c *secureChannel) header(kind byte) []byte {
	b := make([]byte, secureHeader)
	copy(b, secureMagic)
	b[4] = kind
	b[5] = c.role
	copy(b[6:38], c.local[:])
	copy(b[38:70], c.peer[:])
	return b
}
func (c *secureChannel) hello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.header(1)
	return append(b, c.mac(b)...)
}
func (c *secureChannel) keys() error {
	pub, err := ecdh.X25519().NewPublicKey(c.peer[:])
	if err != nil {
		return err
	}
	shared, err := c.private.ECDH(pub)
	if err != nil {
		return err
	}
	seed := append([]byte("PaperFlux/PFS2/keys/"), c.local[:]...)
	seed = append(seed, c.peer[:]...)
	if c.role == 1 {
		seed = append(append([]byte("PaperFlux/PFS2/keys/"), c.peer[:]...), c.local[:]...)
	}
	seed = append(seed, shared...)
	derive := func(direction byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(c.mac(append(append([]byte(nil), seed...), direction)))
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	c.send, err = derive(c.role)
	if err != nil {
		return err
	}
	c.recv, err = derive(1 - c.role)
	return err
}

// receiveHandshake returns an ACK only for an authenticated HELLO.
func (c *secureChannel) receiveHandshake(b []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) != secureHeader+32 || !bytes.Equal(b[:4], secureMagic) || b[5] != 1-c.role ||
		!hmac.Equal(c.mac(b[:secureHeader]), b[secureHeader:]) {
		return nil, errSecure
	}
	var remote [32]byte
	copy(remote[:], b[6:38])
	if remote == ([32]byte{}) || c.retired[remote] {
		return nil, errSecure
	}
	switch b[4] {
	case 1:
		if !c.havePeer || remote != c.peer {
			if len(c.retired) >= 128 {
				return nil, fmt.Errorf("secure peer restart limit reached; restart channel")
			}
			if c.havePeer {
				c.retired[c.peer] = true
			}
			c.peer = remote
			c.havePeer = true
			c.confirmed = false
			c.high = 0
			c.bitmap = 0
			c.seen = false
			if err := c.keys(); err != nil {
				c.havePeer = false
				c.send = nil
				c.recv = nil
				return nil, err
			}
		}
		ack := c.header(2)
		return append(ack, c.mac(ack)...), nil
	case 2:
		if !c.havePeer || remote != c.peer || !bytes.Equal(b[38:70], c.local[:]) {
			return nil, errSecure
		}
		c.confirmed = true
		return nil, nil
	default:
		return nil, errSecure
	}
}
func (c *secureChannel) ready() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.confirmed }

func (c *secureChannel) seal(payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.confirmed || len(payload) > maxSecureFrame || c.seq == ^uint64(0) {
		return nil, errSecure
	}
	c.seq++
	b := c.header(0)
	binary.BigEndian.PutUint64(b[70:78], c.seq)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.seq)
	return c.send.Seal(b, nonce[:], payload, b), nil
}
func (c *secureChannel) open(b []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.confirmed || len(b) < secureHeader+16 || len(b) > maxSecureFrame+secureHeader+16 ||
		!bytes.Equal(b[:4], secureMagic) || b[4] != 0 || b[5] != 1-c.role ||
		!bytes.Equal(b[6:38], c.peer[:]) || !bytes.Equal(b[38:70], c.local[:]) {
		return nil, errSecure
	}
	seq := binary.BigEndian.Uint64(b[70:78])
	if seq == 0 {
		return nil, errSecure
	}
	if c.seen && seq <= c.high && (c.high-seq >= 64 || c.bitmap&(uint64(1)<<(c.high-seq)) != 0) {
		return nil, errSecure
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	plain, err := c.recv.Open(nil, nonce[:], b[secureHeader:], b[:secureHeader])
	if err != nil {
		return nil, errSecure
	}
	if !c.seen {
		c.high = seq
		c.bitmap = 1
		c.seen = true
	} else if seq > c.high {
		if seq-c.high >= 64 {
			c.bitmap = 1
		} else {
			c.bitmap = c.bitmap<<(seq-c.high) | 1
		}
		c.high = seq
	} else {
		c.bitmap |= uint64(1) << (c.high - seq)
	}
	return plain, nil
}
